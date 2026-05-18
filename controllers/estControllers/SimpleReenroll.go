package estControllers

import (
	"encoding/base64"
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

// SimpleReenroll обрабатывает POST /.well-known/est/simplereenroll (RFC 7030).
// Аутентификация через mTLS — клиент предъявляет ранее выпущенный сертификат.
// После успешной выдачи нового сертификата старый отзывается.
func SimpleReenroll(c fiber.Ctx) error {
	oldCert, ok := c.Locals("est_cert").(models.ESTCert)
	if !ok {
		return c.Status(401).SendString("Unauthorized")
	}

	csrDER, err := decodeCSRBody(c.Body())
	if err != nil {
		slog.Error("EST SimpleReenroll: CSR decode error", "error", err)
		return c.Status(400).SendString("Invalid CSR: " + err.Error())
	}

	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("EST SimpleReenroll: database error", "error", err)
		return c.Status(503).SendString("Service unavailable")
	}
	defer db.Close()

	if oldCert.TTL <= 0 {
		return c.Status(500).SendString("Invalid TTL in previous certificate")
	}

	certDER, err := crypts.SignCSR(csrDER, db, oldCert.SigningCAId, oldCert.TTL)
	if err != nil {
		slog.Error("EST SimpleReenroll: signing error", "error", err)
		return c.Status(400).SendString(err.Error())
	}

	// Сохраняем новый сертификат
	if err := saveESTCert(db, oldCert.ESTUserId, oldCert.SigningCAId, oldCert.TTL, certDER); err != nil {
		slog.Error("EST SimpleReenroll: save cert error", "error", err)
		return c.Status(500).SendString("Failed to save certificate")
	}

	// Отзываем старый сертификат
	now := time.Now().Format(time.RFC3339)
	_, err = db.Exec(`UPDATE est_certs SET cert_status = 2, data_revoke = ?, reason_revoke = ?
		WHERE id = ?`, now, "superseded", oldCert.Id)
	if err != nil {
		slog.Error("EST SimpleReenroll: failed to revoke old cert", "error", err, "id", oldCert.Id)
	}

	p7der, err := pkcs7.DegenerateCertificate(certDER)
	if err != nil {
		slog.Error("EST SimpleReenroll: pkcs7 error", "error", err)
		return c.Status(500).SendString("Internal server error")
	}

	slog.Info("EST SimpleReenroll: certificate renewed",
		"old_serial", oldCert.SerialNumber, "cn", oldCert.CommonName)
	c.Set("Content-Type", "application/pkcs7-mime; smime-type=certs-only")
	c.Set("Content-Transfer-Encoding", "base64")
	return c.SendString(base64.StdEncoding.EncodeToString(p7der))
}
