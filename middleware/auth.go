package middleware

import (
	"path/filepath"
	"strings"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
)

// Session store
var Store = session.New()

// Public routes that don't require authentication
var publicRoutes = []string{
	"/",
	"/login",
	"/index",
	"/api/v1/crl",
	"/api/v1/ocsp",
}

// Расширения статических файлов, которые должны быть доступны всем
var staticExtensions = []string{
	".css", ".js", ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".woff", ".woff2", ".ttf", ".eot",
}

// AuthMiddleware checks if the user is authenticated
func AuthMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {
		// Skip middleware for public routes
		path := c.Path()

		// Allow access to static files by extension
		ext := filepath.Ext(path)
		for _, staticExt := range staticExtensions {
			if ext == staticExt {
				return c.Next()
			}
		}

		// Check if the path is in the public routes list
		for _, route := range publicRoutes {
			if path == route || (route == "/api/v1/ocsp" && strings.HasPrefix(path, "/api/v1/ocsp")) {
				return c.Next()
			}
		}

		// Get session
		sess, err := Store.Get(c)
		if err != nil {
			c.Set("Location", "/login")
			return c.SendStatus(fiber.StatusFound)
		}

		// Check if user is authenticated
		auth := sess.Get("authenticated")
		if auth == nil || !auth.(bool) {
			c.Set("Location", "/login")
			return c.SendStatus(fiber.StatusFound)
		}

		return c.Next()
	}
}
