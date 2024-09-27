package controllers

import (
	"github.com/gofiber/fiber/v3"
)

func Index(c fiber.Ctx) error {
	return c.Render("Index", fiber.Map{
		"Title": "Hello, World!",
	})
}
