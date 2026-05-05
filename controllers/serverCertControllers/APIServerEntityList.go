package controllers

import (
	"log/slog"

	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func APIServerEntityList(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	type Entity struct {
		Hostname     string `json:"hostname" db:"hostname"`
		ServerStatus string `json:"server_status" db:"server_status"`
		Path         string `json:"cert_config_path" db:"cert_config_path"`
		Id           int    `json:"id" db:"id"`
	}

	if c.Method() == "GET" {
		entityList := []Entity{}
		err = db.Select(&entityList, "SELECT id, hostname, COALESCE(cert_config_path, '') as cert_config_path , server_status FROM server")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}

		return c.JSON(fiber.Map{"status": "success", "data": entityList})
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
