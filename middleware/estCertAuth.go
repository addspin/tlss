package middleware

import (
	"log/slog"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

// ESTCertAuth проверяет клиентский TLS-сертификат против с данными таблицы est_certs.
// Используется для /.well-known/est/simplereenroll (RFC 7030).
// TLS-цепочка уже проверена сервером (VerifyClientCertIfGiven + ClientCAs).
// Здесь только: наличие сертификата, не отозван ли, и поиск записи в est_certs.
func ESTCertAuth() fiber.Handler {
	return func(c fiber.Ctx) error {
		state := c.RequestCtx().TLSConnectionState()
		if state == nil || len(state.PeerCertificates) == 0 {
			return c.Status(401).SendString("Client certificate required")
		}
		clientCert := state.PeerCertificates[0]
		serial := clientCert.SerialNumber.Text(16)

		database := viper.GetString("database.path")
		db, err := sqlx.Open("sqlite3", database)
		if err != nil {
			slog.Error("ESTCertAuth: database error", "error", err)
			return c.Status(503).SendString("Service unavailable")
		}
		defer db.Close()

		var estCert models.ESTCert
		err = db.Get(&estCert, `SELECT id, est_user_id, serial_number, signing_ca_id,
			common_name, ttl, cert_create_time, cert_expire_time, cert_status
			FROM est_certs WHERE serial_number = ?`, serial)
		if err != nil {
			slog.Warn("ESTCertAuth: cert not found in est_certs", "serial", serial)
			return c.Status(403).SendString("Certificate not recognized")
		}

		if estCert.CertStatus == 2 {
			return c.Status(403).SendString("Certificate revoked")
		}
		if estCert.CertStatus == 1 {
			return c.Status(403).SendString("Certificate expired")
		}

		c.Locals("est_cert", estCert)
		return c.Next()
	}
}
