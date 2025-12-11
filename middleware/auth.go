package middleware

import (
	"path/filepath"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/session"
	"github.com/spf13/viper"
)

// Session store
var Store *session.Store

// InitSessionStore инициализирует хранилище сессий с настройками на основе протокола из конфига
func InitSessionStore() {
	// Автоматически определяем CookieSecure на основе протокола
	isSecure := viper.GetString("app.protocol") == "https"

	Store = session.NewStore(session.Config{
		CookieSameSite:    "Lax",            // Для совместимости с Safari используем Lax
		CookieSecure:      isSecure,         // Автоматически true для HTTPS, false для HTTP
		CookieHTTPOnly:    true,             // Важно для безопасности, куки только для HTTP запросов
		IdleTimeout:       30 * time.Minute, // Время жизни сессии (переименовано из Expiration в Fiber v3)
		CookiePath:        "/",              // Доступность куки на всех путях
		CookieDomain:      "",               // Пустой домен для локальной разработки
		CookieSessionOnly: false,            // Если true, куки будет удалена при закрытии браузера
		// KeyLookup удален в Fiber v3 RC.3, по умолчанию используется cookie:session_id
	})
}

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
