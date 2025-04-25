package controllers

import (
	"log"

	"github.com/addspin/tlss/middleware"
	"github.com/gofiber/fiber/v3"
)

// LogoutController handles user logout
func LogoutController(c fiber.Ctx) error {
	sess, err := middleware.Store.Get(c)
	if err != nil {
		log.Println("Session error:", err)
		c.Set("Location", "/login")
		return c.SendStatus(fiber.StatusFound)
	}

	// Remove authentication
	sess.Delete("authenticated")
	sess.Delete("username")
	if err := sess.Save(); err != nil {
		log.Println("Session save error:", err)
	}

	c.Set("Location", "/login")
	return c.SendStatus(fiber.StatusFound)
}
