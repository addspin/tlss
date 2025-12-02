package controllers

import (
	"log/slog"

	"github.com/addspin/tlss/middleware"
	"github.com/gofiber/fiber/v3"
)

// LogoutController handles user logout
func LogoutController(c fiber.Ctx) error {
	sess, err := middleware.Store.Get(c)
	if err != nil {
		slog.Error("Session error", "error", err)
		c.Set("Location", "/login")
		return c.SendStatus(fiber.StatusFound)
	}

	// Remove authentication
	sess.Delete("authenticated")
	sess.Delete("username")
	if err := sess.Save(); err != nil {
		slog.Error("Session save error", "error", err)
	}

	c.Set("Location", "/login")
	return c.SendStatus(fiber.StatusFound)
}
