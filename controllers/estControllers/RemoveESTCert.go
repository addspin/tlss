package estControllers

import (
	"log/slog"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

// RemoveESTCert удаляет EST сертификат из таблицы est_certs
func RemoveESTCert(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("RemoveESTCert: database error", "error", err)
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
		if data.Id == 0 {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}

		tx := db.MustBegin()
		_, err = tx.Exec(`DELETE FROM est_certs WHERE id = ?`, data.Id)
		if err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error deleting EST certificate: " + err.Error(),
			})
		}
		if err = tx.Commit(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error saving changes: " + err.Error(),
			})
		}
	}
	return c.Render("est/certESTList-tpl", fiber.Map{})
}
