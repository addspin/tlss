package controllers

import (
	"log/slog"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RollbackUserCert(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for remove server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.UserCertsData)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.Id == 0 ||
			data.EntityId == 0 ||
			data.DaysLeft == 0 {

			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields: certificate ID, entity ID, or days until expiration",
			})
		}
		tx := db.MustBegin()
		// Выносим значения из запроса
		currentTime := ""

		var certStatus int
		if data.DaysLeft <= 0 {
			certStatus = 1
		} else {
			certStatus = 0
		}

		// Обновляем статус сертификата с учетом ID сервера и ID сертификата
		_, err = tx.Exec(`UPDATE user_certs SET 
			cert_status = ?, 
			data_revoke = ?,
			reason_revoke = ?
			WHERE id = ? AND entity_id = ?`, certStatus, currentTime, "", data.Id, data.EntityId)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error rolling back certificate: " + err.Error(),
			})
		}

		err = tx.Commit() // Проверяем ошибку при коммите
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error saving changes: " + err.Error(),
			})
		}

		return c.Render("user_revoke_certs/certUserRevokeList-tpl", fiber.Map{})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
