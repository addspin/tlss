package controllers

import (
	"log/slog"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func APIOIDListController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		oidList := []models.OIDData{}
		err := db.Select(&oidList, "SELECT id, TRIM(oid_name) as oid_name, TRIM(oid_description) as oid_description FROM oid")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}

		return c.JSON(fiber.Map{"status": "success", "data": oidList})
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
