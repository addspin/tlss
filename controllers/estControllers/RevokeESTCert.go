package estControllers

import (
	"log/slog"
	"time"

	"github.com/addspin/tlss/crl"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

// RevokeESTCert помечает EST сертификат как отозванный (cert_status = 2)
func RevokeESTCert(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("RevokeESTCert: database error", "error", err)
	}
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.ESTCert)
		if err := c.Bind().JSON(data); err != nil {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Cannot parse JSON",
				"data":    err,
			})
		}
		if data.Id == 0 ||
			data.ESTUserId == 0 ||
			data.ReasonRevoke == "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields: certificate ID, EST user ID or reason",
			})
		}

		tx := db.MustBegin()
		currentTime := time.Now().Format(time.RFC3339)
		certStatus := 2

		_, err = tx.Exec(`UPDATE est_certs SET
			cert_status = ?,
			data_revoke = ?,
			reason_revoke = ?
			WHERE id = ? AND est_user_id = ?`,
			certStatus, currentTime, data.ReasonRevoke, data.Id, data.ESTUserId)
		if err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error revoking EST certificate: " + err.Error(),
			})
		}
		if err = tx.Commit(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error saving changes: " + err.Error(),
			})
		}

		// Пересоздаем CRL сразу после отзыва
		if err := crl.CombinedCRL(db); err != nil {
			slog.Error("RevokeESTCert: CRL regeneration failed", "error", err)
		}
	}
	return c.Render("est/certESTList-tpl", fiber.Map{})
}
