// Package ocsp реализует OCSP-респондер по RFC 6960 с учётом облегчённого
// профиля RFC 5019 (обязательный nextUpdate, unauthorized на неизвестный serial,
// кэшируемые ответы без nonce).
//
// Ответы подписываются ключом самого CA, выпустившего сертификат
// (responderID = byName издателя, RFC 6960 §4.2.2.3) — делегированный
// responder-сертификат не используется.
package ocsp

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/addspin/tlss/crl"
	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
	xocsp "golang.org/x/crypto/ocsp"
)

// scopeKind определяет, за какие сертификаты отвечает конкретный CA
type scopeKind int

const (
	scopeCoreEndEntity scopeKind = iota // Core Sub CA - конечные сертификаты (certs, user_certs, est_certs)
	scopeCoreSubCA                      // Core Root CA - сертификаты Sub CA (ca_certs)
	scopeExternal                       // внешний CA - конечные сертификаты с signing_ca_id = entity_ca_id
)

// caCandidate - CA, способный подписать OCSP-ответ
type caCandidate struct {
	Cert       *x509.Certificate
	Signer     crypto.Signer
	Scope      scopeKind
	EntityCAId int // заполняется только для scopeExternal
}

// certRecord - результат поиска сертификата в базе
type certRecord struct {
	CertStatus   int    `db:"cert_status"`
	DataRevoke   string `db:"data_revoke"`
	ReasonRevoke string `db:"reason_revoke"`
}

// Result - готовый OCSP-ответ вместе с метаданными для HTTP-кэширования (RFC 5019 §6)
type Result struct {
	DER        []byte    // DER-encoded OCSPResponse
	ThisUpdate time.Time // время формирования статуса
	NextUpdate time.Time // до какого момента ответ актуален
	Cacheable  bool      // false для error-ответов (unauthorized, malformed, internalError)
}

// BuildResponse разбирает DER-encoded OCSPRequest и формирует OCSPResponse.
// Ошибки протокола возвращаются как валидные неподписанные OCSPResponse
func BuildResponse(db *sqlx.DB, reqDER []byte) Result {
	req, err := xocsp.ParseRequest(reqDER)
	if err != nil {
		slog.Warn("OCSP: malformed request", "error", err)
		return Result{DER: xocsp.MalformedRequestErrorResponse}
	}

	candidates, err := loadCACandidates(db)
	if err != nil {
		slog.Error("OCSP: no CA available for signing", "error", err)
		return Result{DER: xocsp.InternalErrorErrorResponse}
	}

	serialHex := strings.ToUpper(req.SerialNumber.Text(16))

	ca, ok := matchIssuer(candidates, req)
	if !ok {
		// Запрос про сертификат, выпущенный неизвестным нам CA
		slog.Warn("OCSP: unknown issuer", "serial", serialHex)
		return Result{DER: xocsp.UnauthorizedErrorResponse}
	}

	record, found := lookupSerial(db, ca, serialHex)
	if !found {
		// RFC 5019 §2.2.3: на неизвестный serial отвечаем unauthorized,
		// чтобы респондер нельзя было использовать как оракул для перебора
		slog.Warn("OCSP: serial not found", "serial", serialHex, "issuer", ca.Cert.Subject.CommonName)
		return Result{DER: xocsp.UnauthorizedErrorResponse}
	}

	validity := time.Duration(viper.GetInt("CAocsp.responseValidity")) * time.Hour
	if validity <= 0 {
		validity = 24 * time.Hour
	}

	now := time.Now()
	template := xocsp.Response{
		SerialNumber: req.SerialNumber,
		ThisUpdate:   now,
		NextUpdate:   now.Add(validity), // RFC 5019 §2.2.4: nextUpdate обязателен
		IssuerHash:   req.HashAlgorithm, // должен совпадать с хэшем из запроса
	}

	// cert_status: 0 - valid, 1 - expired, 2 - revoked.
	// RFC 6960 §2.2: OCSP сообщает только об отзыве. Истёкший, но не отозванный
	// сертификат получает статус good - срок действия клиент проверяет сам по NotAfter.
	if record.CertStatus == 2 {
		template.Status = xocsp.Revoked
		template.RevocationReason = crl.GetRevocationReason(record.ReasonRevoke)
		if revokedAt, err := time.Parse(time.RFC3339, record.DataRevoke); err == nil {
			template.RevokedAt = revokedAt
		} else {
			slog.Warn("OCSP: cannot parse revocation time, using current time",
				"serial", serialHex, "data_revoke", record.DataRevoke)
			template.RevokedAt = now
		}
	} else {
		template.Status = xocsp.Good
	}

	// issuer и responderCert совпадают - подписываем ключом самого CA
	respDER, err := xocsp.CreateResponse(ca.Cert, ca.Cert, template, ca.Signer)
	if err != nil {
		slog.Error("OCSP: failed to create response", "error", err, "serial", serialHex)
		return Result{DER: xocsp.InternalErrorErrorResponse}
	}

	slog.Info("OCSP: response created",
		"serial", serialHex,
		"status", statusName(template.Status),
		"issuer", ca.Cert.Subject.CommonName)

	return Result{
		DER:        respDER,
		ThisUpdate: template.ThisUpdate,
		NextUpdate: template.NextUpdate,
		Cacheable:  true,
	}
}

// loadCACandidates собирает все CA, которыми можно подписать ответ:
// Core Sub CA, Core Root CA и активные внешние CA с приватным ключом.
func loadCACandidates(db *sqlx.DB) ([]caCandidate, error) {
	var out []caCandidate

	// Core Sub CA - подписывает конечные сертификаты
	var subCA models.CAData
	if err := db.Get(&subCA, "SELECT * FROM ca_certs WHERE type_ca = 'Sub' AND cert_status = 0"); err == nil {
		cert, signer, err := decodeCAPair(subCA.PublicKey, subCA.PrivateKey)
		if err != nil {
			slog.Error("OCSP: failed to load Core Sub CA", "error", err)
		} else {
			out = append(out, caCandidate{Cert: cert, Signer: signer, Scope: scopeCoreEndEntity})
		}
	}

	// Core Root CA - подписывает сертификаты Sub CA
	var rootCA models.CAData
	if err := db.Get(&rootCA, "SELECT * FROM ca_certs WHERE type_ca = 'Root' AND cert_status = 0"); err == nil {
		cert, signer, err := decodeCAPair(rootCA.PublicKey, rootCA.PrivateKey)
		if err != nil {
			slog.Error("OCSP: failed to load Core Root CA", "error", err)
		} else {
			out = append(out, caCandidate{Cert: cert, Signer: signer, Scope: scopeCoreSubCA})
		}
	}

	// Внешние CA
	var extCAs []models.CAExtData
	if err := db.Select(&extCAs, `SELECT * FROM ca_certs_ext WHERE private_key != '' AND cert_status = 0`); err == nil {
		for _, ext := range extCAs {
			cert, signer, err := decodeCAPair(ext.PublicKey, ext.PrivateKey)
			if err != nil {
				slog.Error("OCSP: failed to load external CA", "entity_ca_id", ext.EntityCAId, "error", err)
				continue
			}
			out = append(out, caCandidate{
				Cert:       cert,
				Signer:     signer,
				Scope:      scopeExternal,
				EntityCAId: ext.EntityCAId,
			})
		}
	}

	if len(out) == 0 {
		return nil, fmt.Errorf("no active CA with private key found")
	}
	return out, nil
}

// decodeCAPair декодирует PEM сертификата и расшифровывает приватный ключ CA
func decodeCAPair(certPEM, storedKey string) (*x509.Certificate, crypto.Signer, error) {
	certBlock, _ := pem.Decode([]byte(certPEM))
	if certBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	keyPEM := []byte(storedKey)
	if len(crypts.AesSecretKey.Key) > 0 {
		aes := crypts.Aes{}
		decrypted, err := aes.Decrypt([]byte(storedKey), crypts.AesSecretKey.Key)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to decrypt private key: %w", err)
		}
		keyPEM = decrypted
	}

	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("failed to decode private key PEM")
	}

	var parsed any
	switch keyBlock.Type {
	case "RSA PRIVATE KEY":
		parsed, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		parsed, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	case "PRIVATE KEY":
		parsed, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	default:
		return nil, nil, fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	signer, ok := parsed.(crypto.Signer)
	if !ok {
		return nil, nil, fmt.Errorf("private key does not implement crypto.Signer")
	}
	return cert, signer, nil
}

// matchIssuer находит CA, которому адресован запрос, сравнивая
// IssuerNameHash и IssuerKeyHash из запроса (RFC 6960 §4.1.1)
func matchIssuer(candidates []caCandidate, req *xocsp.Request) (caCandidate, bool) {
	for _, ca := range candidates {
		nameHash, keyHash, err := issuerHashes(ca.Cert, req.HashAlgorithm)
		if err != nil {
			slog.Error("OCSP: failed to compute issuer hashes",
				"cn", ca.Cert.Subject.CommonName, "error", err)
			continue
		}
		if bytesEqual(nameHash, req.IssuerNameHash) && bytesEqual(keyHash, req.IssuerKeyHash) {
			return ca, true
		}
	}
	return caCandidate{}, false
}

// issuerHashes вычисляет IssuerNameHash и IssuerKeyHash по RFC 6960 §4.1.1:
//
//	IssuerNameHash - хэш DER-представления Subject издателя
//	IssuerKeyHash  - хэш содержимого BIT STRING subjectPublicKey (без тега и unused bits)
func issuerHashes(cert *x509.Certificate, h crypto.Hash) (nameHash, keyHash []byte, err error) {
	if !h.Available() {
		return nil, nil, fmt.Errorf("hash algorithm %v is not available", h)
	}

	nh := h.New()
	nh.Write(cert.RawSubject)
	nameHash = nh.Sum(nil)

	var spki struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err != nil {
		return nil, nil, fmt.Errorf("failed to parse SubjectPublicKeyInfo: %w", err)
	}
	kh := h.New()
	kh.Write(spki.SubjectPublicKey.RightAlign())
	keyHash = kh.Sum(nil)

	return nameHash, keyHash, nil
}

// lookupSerial ищет сертификат по серийному номеру в таблицах,
// относящихся к области ответственности найденного CA
func lookupSerial(db *sqlx.DB, ca caCandidate, serialHex string) (certRecord, bool) {
	const cols = `SELECT cert_status,
		COALESCE(data_revoke, '')   AS data_revoke,
		COALESCE(reason_revoke, '') AS reason_revoke`

	type queryWithArgs struct {
		sql  string
		args []any
	}
	var queries []queryWithArgs

	switch ca.Scope {
	case scopeCoreSubCA:
		// Root CA отвечает за статус выпущенных им Sub CA
		queries = []queryWithArgs{
			{cols + ` FROM ca_certs WHERE serial_number = ? AND type_ca = 'Sub'`, []any{serialHex}},
		}

	case scopeCoreEndEntity:
		// Core Sub CA отвечает за конечные сертификаты с signing_ca_id = 0
		queries = []queryWithArgs{
			{cols + ` FROM certs      WHERE serial_number = ? AND signing_ca_id = 0`, []any{serialHex}},
			{cols + ` FROM user_certs WHERE serial_number = ? AND signing_ca_id = 0`, []any{serialHex}},
			{cols + ` FROM est_certs  WHERE serial_number = ? AND signing_ca_id = 0`, []any{serialHex}},
		}

	case scopeExternal:
		// Внешний CA отвечает за конечные сертификаты со своим entity_ca_id
		queries = []queryWithArgs{
			{cols + ` FROM certs      WHERE serial_number = ? AND signing_ca_id = ?`, []any{serialHex, ca.EntityCAId}},
			{cols + ` FROM user_certs WHERE serial_number = ? AND signing_ca_id = ?`, []any{serialHex, ca.EntityCAId}},
			{cols + ` FROM est_certs  WHERE serial_number = ? AND signing_ca_id = ?`, []any{serialHex, ca.EntityCAId}},
		}
	}

	for _, q := range queries {
		var rec certRecord
		if err := db.Get(&rec, q.sql, q.args...); err == nil {
			return rec, true
		}
	}
	return certRecord{}, false
}

// bytesEqual сравнивает два байтовых среза
func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// statusName возвращает текстовое имя статуса для логов
func statusName(status int) string {
	switch status {
	case xocsp.Good:
		return "good"
	case xocsp.Revoked:
		return "revoked"
	case xocsp.Unknown:
		return "unknown"
	default:
		return fmt.Sprintf("status(%d)", status)
	}
}
