package apiKeyControllers

import (
	"log/slog"

	"github.com/addspin/tlss/middleware"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

// RemoveAPIKey удаляет API ключ из БД и возвращает обновлённый список (HTMX)
func RemoveAPIKey(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("RemoveAPIKey: database connection error", "error", err)
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Database connection error"})
	}
	defer db.Close()

	data := new(models.APIKey)
	if err := c.Bind().JSON(data); err != nil {
		return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Cannot parse JSON"})
	}
	if data.Id == 0 {
		return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Missing API key ID"})
	}

	_, err = db.Exec("DELETE FROM api_keys WHERE id = ?", data.Id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Error deleting API key: " + err.Error()})
	}

	middleware.APIKeyStore.DeleteByID(data.Id)

	slog.Info("RemoveAPIKey: API key deleted", "id", data.Id)

	keys := fetchAPIKeys(db)
	return c.Render("api_keys/apiKeyList", fiber.Map{
		"apiKeys": keys,
	})
}
