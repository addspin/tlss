package apiKeyControllers

import (
	"github.com/gofiber/fiber/v3"
)

func APIExamplesController(c fiber.Ctx) error {
	// database := viper.GetString("database.path")
	// db, err := sqlx.Open("sqlite3", database)
	// if err != nil {
	// 	slog.Error("APIKeyController: database connection error", "error", err)
	// 	return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Database connection error"})
	// }
	// defer db.Close()

	data := fiber.Map{
		"Title": "API examples",
	}
	if c.Get("HX-Request") != "" {
		return c.Render("apiExamples-content", data, "")
	}

	if c.Method() == "GET" {
		return c.Render("api_keys/apiExamples", data)
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
