package controllers

import (
	"log/slog"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RemoveCert(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for remove server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}

	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.CertsData)
		err := c.Bind().JSON(data)

		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		tx := db.MustBegin()

		dataRemove := `DELETE FROM certs WHERE id = ?`
		_, err = tx.Exec(dataRemove, data.Id)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error deleting certificate: " + err.Error(),
			})
		}
		err = tx.Commit() // Проверяем ошибку при коммите
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error saving changes: " + err.Error(),
			})
		}
	}
	return c.Render("add_certs/certList-tpl", fiber.Map{})
}
