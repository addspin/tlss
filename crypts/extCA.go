package crypts

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
)

// CertKeyPair связывает сертификат с его приватным ключом
type CertKeyPair struct {
	Cert *x509.Certificate
	Key  crypto.PrivateKey // может быть nil если ключ не предоставлен
}

// ParsePEMFiles разбирает массив файлов (байты), извлекает сертификаты и приватные ключи
func ParsePEMFiles(files [][]byte) ([]*x509.Certificate, []crypto.PrivateKey, error) {
	var certs []*x509.Certificate
	var keys []crypto.PrivateKey

	for i, fileData := range files {
		rest := fileData
		foundAny := false

		for len(rest) > 0 {
			var block *pem.Block
			block, rest = pem.Decode(rest)
			if block == nil {
				break
			}
			foundAny = true

			switch block.Type {
			case "CERTIFICATE":
				cert, err := x509.ParseCertificate(block.Bytes)
				if err != nil {
					return nil, nil, fmt.Errorf("file %d: failed to parse certificate: %w", i+1, err)
				}
				certs = append(certs, cert)

			case "RSA PRIVATE KEY":
				key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
				if err != nil {
					return nil, nil, fmt.Errorf("file %d: failed to parse RSA private key: %w", i+1, err)
				}
				keys = append(keys, key)

			case "EC PRIVATE KEY":
				key, err := x509.ParseECPrivateKey(block.Bytes)
				if err != nil {
					return nil, nil, fmt.Errorf("file %d: failed to parse EC private key: %w", i+1, err)
				}
				keys = append(keys, key)

			case "PRIVATE KEY":
				key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
				if err != nil {
					return nil, nil, fmt.Errorf("file %d: failed to parse PKCS8 private key: %w", i+1, err)
				}
				privKey, ok := key.(crypto.PrivateKey)
				if !ok {
					return nil, nil, fmt.Errorf("file %d: unsupported private key type", i+1)
				}
				keys = append(keys, privKey)

			default:
				slog.Warn("ParsePEMFiles: skipping unknown PEM block type", "type", block.Type, "file", i+1)
			}
		}

		if !foundAny {
			return nil, nil, fmt.Errorf("file %d: no valid PEM blocks found", i+1)
		}
	}

	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("no certificates found in uploaded files")
	}

	return certs, keys, nil
}

// publicKeyEqual сравнивает публичные ключи двух объектов
func publicKeyEqual(certPub, keyPub crypto.PublicKey) bool {
	switch pub := certPub.(type) {
	case *rsa.PublicKey:
		keyRSA, ok := keyPub.(*rsa.PublicKey)
		if !ok {
			return false
		}
		return pub.N.Cmp(keyRSA.N) == 0 && pub.E == keyRSA.E
	case *ecdsa.PublicKey:
		keyEC, ok := keyPub.(*ecdsa.PublicKey)
		if !ok {
			return false
		}
		return pub.X.Cmp(keyEC.X) == 0 && pub.Y.Cmp(keyEC.Y) == 0
	case ed25519.PublicKey:
		keyED, ok := keyPub.(ed25519.PublicKey)
		if !ok {
			return false
		}
		return pub.Equal(keyED)
	}
	return false
}

// getPublicKey извлекает публичный ключ из приватного
func getPublicKey(key crypto.PrivateKey) crypto.PublicKey {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	case ed25519.PrivateKey:
		return k.Public()
	case *ed25519.PrivateKey:
		return (*k).Public()
	}
	return nil
}

// MatchKeysToCerts сопоставляет приватные ключи с сертификатами по публичному ключу
func MatchKeysToCerts(certs []*x509.Certificate, keys []crypto.PrivateKey) []CertKeyPair {
	pairs := make([]CertKeyPair, 0, len(certs))
	usedKeys := make(map[int]bool)

	for _, cert := range certs {
		pair := CertKeyPair{Cert: cert}
		for i, key := range keys {
			if usedKeys[i] {
				continue
			}
			keyPub := getPublicKey(key)
			if keyPub != nil && publicKeyEqual(cert.PublicKey, keyPub) {
				pair.Key = key
				usedKeys[i] = true
				break
			}
		}
		pairs = append(pairs, pair)
	}

	return pairs
}

// DetectAlgorithm определяет алгоритм и длину ключа из сертификата
func DetectAlgorithm(cert *x509.Certificate) (algorithm string, keyLength int) {
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		return "RSA", pub.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", pub.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "ED25519", 256
	}
	return "Unknown", 0
}

// DetermineCAType определяет тип CA (Root или Sub) на основе свойств сертификата
func DetermineCAType(cert *x509.Certificate) string {
	// Self-signed = Root CA
	if cert.Issuer.CommonName == cert.Subject.CommonName &&
		cert.AuthorityKeyId != nil &&
		cert.SubjectKeyId != nil &&
		string(cert.AuthorityKeyId) == string(cert.SubjectKeyId) {
		return "Root"
	}
	// Проверяем по IsCA
	if cert.IsCA {
		// Если issuer != subject — это Sub/Intermediate CA
		if cert.Issuer.CommonName != cert.Subject.CommonName {
			return "Sub"
		}
		// Self-signed CA
		return "Root"
	}
	return "Sub"
}

// standardizeSerialNumberExt возвращает серийный номер в стандартизированном формате
func standardizeSerialNumberExt(serialNumber *big.Int) string {
	hexStr := serialNumber.Text(16)
	return strings.ToUpper(hexStr)
}

// BuildCAExtRecords создаёт записи CAExtData из пар сертификат-ключ
func BuildCAExtRecords(pairs []CertKeyPair, entityCAId int) ([]models.CAExtData, error) {
	records := make([]models.CAExtData, 0, len(pairs))
	aes := Aes{}

	for _, pair := range pairs {
		cert := pair.Cert

		// Проверяем что это CA-сертификат
		if !cert.IsCA {
			slog.Warn("BuildCAExtRecords: skipping non-CA certificate", "cn", cert.Subject.CommonName)
			continue
		}

		algorithm, keyLength := DetectAlgorithm(cert)
		typeCA := DetermineCAType(cert)

		// Кодируем сертификат в PEM
		certPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		})

		// Кодируем и шифруем приватный ключ если он есть
		var encryptedKeyStr string
		if pair.Key != nil {
			keyBytes, err := x509.MarshalPKCS8PrivateKey(pair.Key)
			if err != nil {
				return nil, fmt.Errorf("failed to marshal private key for %s: %w", cert.Subject.CommonName, err)
			}
			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "PRIVATE KEY",
				Bytes: keyBytes,
			})

			if len(AesSecretKey.Key) > 0 {
				encrypted, err := aes.Encrypt(keyPEM, AesSecretKey.Key)
				if err != nil {
					return nil, fmt.Errorf("failed to encrypt private key for %s: %w", cert.Subject.CommonName, err)
				}
				encryptedKeyStr = string(encrypted)
			} else {
				slog.Warn("BuildCAExtRecords: saving key without encryption", "cn", cert.Subject.CommonName)
				encryptedKeyStr = string(keyPEM)
			}
		}

		// Вычисляем days_left
		daysLeft := int(time.Until(cert.NotAfter).Hours() / 24)
		certStatus := 0
		if time.Now().After(cert.NotAfter) {
			certStatus = 1
		}

		record := models.CAExtData{
			EntityCAId:     entityCAId,
			TypeCA:         typeCA,
			CommonName:     cert.Subject.CommonName,
			PublicKey:      string(certPEM),
			PrivateKey:     encryptedKeyStr,
			CertCreateTime: cert.NotBefore.Format(time.RFC3339),
			CertExpireTime: cert.NotAfter.Format(time.RFC3339),
			DaysLeft:       daysLeft,
			SerialNumber:   standardizeSerialNumberExt(cert.SerialNumber),
			CertStatus:     certStatus,
			Algorithm:      algorithm,
			KeyLength:      keyLength,
		}
		records = append(records, record)
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no valid CA certificates found in uploaded files")
	}

	return records, nil
}

// ExtractExtCA извлекает подписывающий CA для заданного entity_ca_id
// Возвращает сертификат и приватный ключ самого нижнего CA в цепочке (Sub > Root)
func ExtractExtCA(db *sqlx.DB, entityCAId int) (*x509.Certificate, crypto.PrivateKey, error) {
	var records []models.CAExtData
	err := db.Select(&records,
		`SELECT * FROM ca_certs_ext
		 WHERE entity_ca_id = ? AND private_key != '' AND cert_status = 0
		 ORDER BY CASE type_ca WHEN 'Sub' THEN 1 WHEN 'Intermediate' THEN 2 WHEN 'Root' THEN 3 ELSE 4 END`,
		entityCAId)
	if err != nil {
		return nil, nil, fmt.Errorf("ExtractExtCA: failed to query external CA: %w", err)
	}
	if len(records) == 0 {
		return nil, nil, fmt.Errorf("ExtractExtCA: no active external CA with private key found for entity_ca_id=%d", entityCAId)
	}

	// Берём первую запись (Sub приоритетнее Root)
	record := records[0]

	// Декодируем сертификат
	certBlock, _ := pem.Decode([]byte(record.PublicKey))
	if certBlock == nil {
		return nil, nil, fmt.Errorf("ExtractExtCA: failed to decode certificate PEM")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, nil, fmt.Errorf("ExtractExtCA: failed to parse certificate: %w", err)
	}

	// Расшифровываем приватный ключ
	aes := Aes{}
	var keyPEM []byte
	if len(AesSecretKey.Key) > 0 {
		keyPEM, err = aes.Decrypt([]byte(record.PrivateKey), AesSecretKey.Key)
		if err != nil {
			return nil, nil, fmt.Errorf("ExtractExtCA: failed to decrypt private key: %w", err)
		}
	} else {
		keyPEM = []byte(record.PrivateKey)
	}

	// Декодируем приватный ключ — поддерживаем PKCS8 и PKCS1
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, nil, fmt.Errorf("ExtractExtCA: failed to decode private key PEM")
	}

	var privKey crypto.PrivateKey
	switch keyBlock.Type {
	case "PRIVATE KEY":
		privKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	case "RSA PRIVATE KEY":
		privKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	case "EC PRIVATE KEY":
		privKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	default:
		return nil, nil, fmt.Errorf("ExtractExtCA: unsupported private key type: %s", keyBlock.Type)
	}
	if err != nil {
		return nil, nil, fmt.Errorf("ExtractExtCA: failed to parse private key: %w", err)
	}

	slog.Info("ExtractExtCA: loaded external CA", "cn", cert.Subject.CommonName, "type", record.TypeCA, "entity_ca_id", entityCAId)
	return cert, privKey, nil
}
