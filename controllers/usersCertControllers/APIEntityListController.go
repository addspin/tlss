package controllers

import (
	"log/slog"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func APIEntityListController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		entityList := []models.EntityData{}
		err := db.Select(&entityList, "SELECT id, TRIM(entity_name) as entity_name, TRIM(entity_description) as entity_description FROM entity")
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
