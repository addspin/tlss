package middleware

import (
	"path/filepath"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
)

// Session store
// var Store = session.New()

// Используем явные настройки для совместимости со всеми браузерами, особенно Safari
var Store = session.New(session.Config{
	CookieSameSite:    "Lax",            // Для совместимости с Safari используем Lax
	CookieSecure:      true,             // В production должно быть true если используется HTTPS
	CookieHTTPOnly:    true,             // Важно для безопасности, куки только для HTTP запросов
	Expiration:        30 * time.Minute, // Время жизни сессии
	CookiePath:        "/",              // Доступность куки на всех путях
	CookieDomain:      "",               // Пустой домен для локальной разработки
	KeyLookup:         "cookie:session_id",
	CookieSessionOnly: false, // Если true, куки будет удалена при закрытии браузера
})

// Public routes that don't require authentication
var publicRoutes = []string{
	"/",
	"/login",
	"/overview",
	"/cert_info",
	"/api/v1/crl/subca/der",
	"/api/v1/crl/rootca/der",
	"/api/v1/crl/subca/pem",
	"/api/v1/crl/rootca/pem",
	"/api/v1/crl/bundleca/der",
	"/api/v1/crl/bundleca/pem",
}

// Расширения статических файлов, которые должны быть доступны всем
var staticExtensions = []string{
	".css", ".js", ".svg", ".ico", ".woff", ".woff2", ".ttf",
}

// AuthMiddleware checks if the user is authenticated
func AuthMiddleware() fiber.Handler {
	return func(c fiber.Ctx) error {

		// Проверка API ключа
		apiKey := c.Get("X-API-Key")
		if apiKey == crypts.GetInternalAPIKey() && apiKey != "" {
			return c.Next() // Разрешаем доступ, если ключ верный
		}
		// Skip middleware for public routes
		path := c.Path()
		// логирование запроса
		// userAgent := c.Get("User-Agent")
		// log.Printf("Запрос: %s, путь: %s, User-Agent: %s", c.Method(), path, userAgent)

		// Allow access to static files by extension
		ext := filepath.Ext(path)
		for _, staticExt := range staticExtensions {
			if ext == staticExt {
				return c.Next()
			}
		}

		// Check if the path is in the public routes list
		for _, route := range publicRoutes {
			if path == route {
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

// IsAuthenticated проверяет, авторизован ли пользователь
func IsAuthenticated(c fiber.Ctx) bool {
	sess, err := Store.Get(c)
	if err != nil {
		return false
	}

	auth := sess.Get("authenticated")
	if auth == nil {
		return false
	}

	return auth.(bool)
}
