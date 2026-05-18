package estControllers

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log/slog"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"go.mozilla.org/pkcs7"
)

// SimpleEnroll обрабатывает POST /.well-known/est/simpleenroll (RFC 7030)
// Принимает PKCS#10 CSR (base64 DER), возвращает подписанный сертификат в PKCS#7.
func SimpleEnroll(c fiber.Ctx) error {
	estUser, ok := c.Locals("est_user").(models.ESTUser)
	if !ok {
		return c.Status(401).SendString("Unauthorized")
	}

	csrDER, err := decodeCSRBody(c.Body())
	if err != nil {
		slog.Error("EST SimpleEnroll: CSR decode error", "error", err)
		return c.Status(400).SendString("Invalid CSR: " + err.Error())
	}

	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("EST SimpleEnroll: database error", "error", err)
		return c.Status(503).SendString("Service unavailable")
	}
	defer db.Close()

	ttlDays := viper.GetInt("est.cert_ttl_enrollment")
	if ttlDays <= 0 {
		ttlDays = 365
	}

	certDER, err := crypts.SignCSR(csrDER, db, estUser.SigningCAId, ttlDays)
	if err != nil {
		slog.Error("EST SimpleEnroll: signing error", "error", err)
		return c.Status(400).SendString(err.Error())
	}

	// Сохраняем выпущенный сертификат в est_certs (для mTLS reenroll и отзыва)
	if err := saveESTCert(db, estUser.Id, estUser.SigningCAId, ttlDays, certDER); err != nil {
		slog.Error("EST SimpleEnroll: save cert error", "error", err)
		return c.Status(500).SendString("Failed to save certificate")
	}

	// Уменьшаем счётчик использований, при достижении 0 переводим пользователя в disabled (3)
	if estUser.MaxUses > 0 {
		_, err = db.Exec(`UPDATE est_users SET
			max_uses = max_uses - 1,
			user_status = CASE WHEN max_uses - 1 <= 0 THEN 3 ELSE user_status END
			WHERE id = ?`, estUser.Id)
		if err != nil {
			slog.Error("Error update max_uses in est_users", "error", err)
		}
	}

	p7der, err := pkcs7.DegenerateCertificate(certDER)
	if err != nil {
		slog.Error("EST SimpleEnroll: pkcs7 error", "error", err)
		return c.Status(500).SendString("Internal server error")
	}

	slog.Info("EST SimpleEnroll: certificate issued", "user", estUser.Username)
	c.Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	c.Set("Content-Transfer-Encoding", "base64")
	return c.SendString(base64.StdEncoding.EncodeToString(p7der))
}

// saveESTCert сохраняет выпущенный EST-сертификат в таблицу est_certs.
func saveESTCert(db *sqlx.DB, estUserId int, signingCAId int, ttlDays int, certDER []byte) error {
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("parse cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	algorithm, keyLength := publicKeyInfo(cert.PublicKey)

	now := time.Now()
	daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)

	_, err = db.Exec(`INSERT INTO est_certs
		(est_user_id, serial_number, signing_ca_id, common_name, public_key,
		 algorithm, key_length, ttl, cert_create_time, cert_expire_time, days_left, cert_status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
		estUserId,
		cert.SerialNumber.Text(16),
		signingCAId,
		cert.Subject.CommonName,
		string(certPEM),
		algorithm,
		keyLength,
		ttlDays,
		cert.NotBefore.Format(time.RFC3339),
		cert.NotAfter.Format(time.RFC3339),
		daysLeft,
	)
	return err
}

// publicKeyInfo возвращает алгоритм и длину ключа в битах.
func publicKeyInfo(pub any) (string, int) {
	switch k := pub.(type) {
	case *rsa.PublicKey:
		return "RSA", k.N.BitLen()
	case *ecdsa.PublicKey:
		return "ECDSA", k.Curve.Params().BitSize
	case ed25519.PublicKey:
		return "ED25519", len(k) * 8
	}
	return "", 0
}

// decodeCSRBody разбирает тело запроса: base64 DER, PEM или raw DER.
func decodeCSRBody(body []byte) ([]byte, error) {
	// Пробуем base64
	der, err := base64.StdEncoding.DecodeString(string(body))
	if err == nil {
		return der, nil
	}

	// Пробуем PEM
	block, _ := pem.Decode(body)
	if block != nil {
		return block.Bytes, nil
	}

	// Предполагаем raw DER
	return body, nil
}
