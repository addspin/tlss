package estControllers

import (
	"log/slog"

	"github.com/addspin/tlss/crl"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

// RollbackESTCert возвращает отозванный EST сертификат в статус valid/expired
func RollbackESTCert(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("RollbackESTCert: database error", "error", err)
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
			data.DaysLeft == 0 {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields: cert ID, EST user ID, days left",
			})
		}

		var certStatus int
		if data.DaysLeft <= 0 {
			certStatus = 1
		} else {
			certStatus = 0
		}

		tx := db.MustBegin()
		_, err = tx.Exec(`UPDATE est_certs SET
			cert_status = ?,
			data_revoke = ?,
			reason_revoke = ?
			WHERE id = ? AND est_user_id = ?`,
			certStatus, "", "", data.Id, data.ESTUserId)
		if err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error rolling back EST certificate: " + err.Error(),
			})
		}
		if err = tx.Commit(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error saving changes: " + err.Error(),
			})
		}

		// Пересоздаем CRL - после rollback, убираем из CRL
		if err := crl.CombinedCRL(db); err != nil {
			slog.Error("RollbackESTCert: CRL regeneration failed", "error", err)
		}
		return c.Render("est_revoke_certs/certESTRevokeList-tpl", fiber.Map{})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
