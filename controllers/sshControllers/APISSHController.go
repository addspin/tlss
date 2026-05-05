package sshControllers

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

// APISSHCertListController обрабатывает запросы на получение списка ssh ключей
func APISSHCertListController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	type SSHKey struct {
		ID         int    `json:"id" db:"id"`
		NameSSHKey string `json:"name_ssh_key" db:"name_ssh_key"`
		Algorithm  string `json:"algorithm" db:"algorithm"`
		KeyLength  int    `json:"key_length" db:"key_length"`
	}

	if c.Method() == "GET" {
		sshKeyList := []SSHKey{}
		err = db.Select(&sshKeyList, "SELECT id, name_ssh_key, algorithm, key_length FROM ssh_key")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}

		return c.JSON(fiber.Map{"status": "success", "data": sshKeyList})
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
