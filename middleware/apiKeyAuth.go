package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

const APIKeyPrefix = "tlss_"

// HashKey считает HMAC-SHA256(AesSecretKey, plaintext) и возвращает hex-строку.
func HashKey(plaintext string) (string, error) {
	secret := crypts.AesSecretKey.Key
	if len(secret) == 0 {
		return "", errors.New("server secret not initialized")
	}
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(plaintext))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// APIKeyAuth возвращает middleware для проверки API ключа из заголовка X-API-Key или Authorization: Bearer.
func APIKeyAuth(requiredScope string) fiber.Handler {
	return func(c fiber.Ctx) error {
		rawKey := extractAPIKey(c)
		if rawKey == "" {
			return c.Status(401).JSON(fiber.Map{"status": "error", "message": "API key required"})
		}

		if !strings.HasPrefix(rawKey, APIKeyPrefix) || len(rawKey) < len(APIKeyPrefix)+8 {
			return c.Status(401).JSON(fiber.Map{"status": "error", "message": "Invalid API key format"})
		}

		hashHex, err := HashKey(rawKey)
		if err != nil {
			slog.Error("APIKeyAuth: hash error", "error", err)
			return c.Status(503).JSON(fiber.Map{"status": "error", "message": "Server not unlocked"})
		}

		database := viper.GetString("database.path")
		db, err := sqlx.Open("sqlite3", database)
		if err != nil {
			slog.Error("APIKeyAuth: database connection error", "error", err)
			return c.Status(503).JSON(fiber.Map{"status": "error", "message": "Database unavailable"})
		}
		defer db.Close()

		var k models.APIKey
		err = db.Get(&k, `SELECT id, name, scopes,
			COALESCE(expires_at, '')   AS expires_at,
			COALESCE(key_status, 0)    AS key_status,
			COALESCE(last_used_at, '') AS last_used_at,
			COALESCE(last_used_ip, '') AS last_used_ip
			FROM api_keys WHERE key_hash = ?`, hashHex)
		if err != nil {
			return c.Status(401).JSON(fiber.Map{"status": "error", "message": "Invalid API key"})
		}

		if k.KeyStatus == 1 {
			return c.Status(401).JSON(fiber.Map{"status": "error", "message": "API key expired"})
		}

		if k.ExpiresAt != "" {
			if t, perr := time.Parse(time.RFC3339, k.ExpiresAt); perr == nil && time.Now().After(t) {
				return c.Status(401).JSON(fiber.Map{"status": "error", "message": "API key expired"})
			}
		}

		if requiredScope != "" && !hasScope(k.Scopes, requiredScope) {
			return c.Status(403).JSON(fiber.Map{"status": "error", "message": "Insufficient scope"})
		}

		go updateLastUsed(k.Id, c.IP())
		c.Locals("api_key_name", k.Name)
		c.Locals("api_key_id", k.Id)
		return c.Next()
	}
}

func extractAPIKey(c fiber.Ctx) string {
	if k := c.Get("X-API-Key"); k != "" {
		return k
	}
	auth := c.Get("Authorization")
	if strings.HasPrefix(auth, "Bearer ") {
		return strings.TrimPrefix(auth, "Bearer ")
	}
	return ""
}

func hasScope(scopes string, required string) bool {
	if scopes == "" {
		return false
	}
	for _, s := range strings.Split(scopes, ",") {
		s = strings.TrimSpace(s)
		if s == "admin" || s == required {
			return true
		}
	}
	return false
}

func updateLastUsed(id int, ip string) {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		return
	}
	defer db.Close()
	now := time.Now().Format(time.RFC3339)
	_, _ = db.Exec("UPDATE api_keys SET last_used_at = ?, last_used_ip = ? WHERE id = ?", now, ip, id)
}
