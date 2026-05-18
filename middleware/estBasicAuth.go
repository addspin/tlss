package middleware

import (
	"encoding/base64"
	"log/slog"
	"strings"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

// ESTBasicAuth проверяет данные из HTTP Basic Auth с данными таблицы est_users.
// При успехе кладёт models.ESTUser в c.Locals("est_user").
func ESTBasicAuth() fiber.Handler {
	return func(c fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Basic ") {
			c.Set("WWW-Authenticate", `Basic realm="EST"`)
			return c.Status(401).SendString("Unauthorized")
		}

		decoded, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(authHeader, "Basic "))
		if err != nil {
			c.Set("WWW-Authenticate", `Basic realm="EST"`)
			return c.Status(401).SendString("Unauthorized")
		}

		parts := strings.SplitN(string(decoded), ":", 2)
		if len(parts) != 2 {
			c.Set("WWW-Authenticate", `Basic realm="EST"`)
			return c.Status(401).SendString("Unauthorized")
		}
		username, password := parts[0], parts[1]

		database := viper.GetString("database.path")
		db, err := sqlx.Open("sqlite3", database)
		if err != nil {
			slog.Error("ESTBasicAuth: database error", "error", err)
			return c.Status(503).SendString("Service unavailable")
		}
		defer db.Close()

		var user models.ESTUser
		err = db.Get(&user, `SELECT id, username, password_hash, max_uses, user_status,
			ttl, signing_ca_id FROM est_users WHERE username = ?`, username)
		if err != nil {
			c.Set("WWW-Authenticate", `Basic realm="EST"`)
			return c.Status(401).SendString("Unauthorized")
		}

		if user.UserStatus != 0 {
			return c.Status(401).SendString("Account expired")
		}
		if user.MaxUses == 0 {
			return c.Status(401).SendString("Account disabled")
		}

		if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
			c.Set("WWW-Authenticate", `Basic realm="EST"`)
			return c.Status(401).SendString("Unauthorized")
		}

		c.Locals("est_user", user)
		return c.Next()
	}
}
