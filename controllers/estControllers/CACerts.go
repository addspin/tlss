package estControllers

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"log/slog"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"go.mozilla.org/pkcs7"
)

// CACerts обрабатывает GET /.well-known/est/cacerts
// Возвращает цепочку CA сертификатов в PKCS#7 certs-only (RFC 7030)
func CACerts(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("EST CACerts: database error", "error", err)
		return c.Status(500).SendString("Internal server error")
	}
	defer db.Close()

	var caCerts []models.CAData
	err = db.Select(&caCerts, `SELECT public_key FROM ca_certs WHERE cert_status = 0 ORDER BY type_ca DESC`)
	if err != nil || len(caCerts) == 0 {
		slog.Error("EST CACerts: failed to get CA certs", "error", err)
		return c.Status(500).SendString("CA certificates not available")
	}

	var certs []*x509.Certificate
	for _, ca := range caCerts {
		block, _ := pem.Decode([]byte(ca.PublicKey))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return c.Status(500).SendString("No valid CA certificates found")
	}

	// Строим degenerate PKCS#7 SignedData (только сертификаты)
	sd, err := pkcs7.NewSignedData([]byte{})
	if err != nil {
		slog.Error("EST CACerts: pkcs7 init error", "error", err)
		return c.Status(500).SendString("Internal server error")
	}
	for _, cert := range certs {
		sd.AddCertificate(cert)
	}
	p7der, err := sd.Finish()
	if err != nil {
		slog.Error("EST CACerts: pkcs7 finish error", "error", err)
		return c.Status(500).SendString("Internal server error")
	}

	c.Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	c.Set("Content-Transfer-Encoding", "base64")
	return c.SendString(base64.StdEncoding.EncodeToString(p7der))
}
