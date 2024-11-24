package controllers

import (
	"github.com/gofiber/fiber/v3"
)

func Index(c fiber.Ctx) error {
	return c.Render("index/index", fiber.Map{
		"Title": "Index",
	})
}
