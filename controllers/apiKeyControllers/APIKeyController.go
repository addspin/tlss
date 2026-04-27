package apiKeyControllers

import (
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"strings"
	"time"

	"github.com/addspin/tlss/middleware"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

// APIKeyController обрабатывает GET (страница) и POST (создание ключа)
func APIKeyController(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("APIKeyController: database connection error", "error", err)
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Database connection error"})
	}
	defer db.Close()

	if c.Method() == "POST" {
		return handleCreateAPIKey(c, db)
	}

	keys := fetchAPIKeys(db)

	data := fiber.Map{
		"Title":   "API keys",
		"apiKeys": keys,
	}

	if c.Get("HX-Request") != "" {
		return c.Render("apiKeys-content", data, "")
	}
	return c.Render("api_keys/apiKeys", data)
}

// APIKeyListController возвращает фрагмент таблицы со списком ключей (HTMX)
func APIKeyListController(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("APIKeyListController: database connection error", "error", err)
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Database connection error"})
	}
	defer db.Close()

	keys := fetchAPIKeys(db)
	return c.Render("api_keys/apiKeyList", fiber.Map{
		"apiKeys": keys,
	})
}

func handleCreateAPIKey(c fiber.Ctx, db *sqlx.DB) error {
	type createReq struct {
		Name        string `json:"Name"`
		Scopes      string `json:"Scopes"`
		ExpiresDays int    `json:"ExpiresDays"`
	}
	req := new(createReq)
	if err := c.Bind().JSON(req); err != nil {
		return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Cannot parse JSON"})
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Name is required"})
	}
	if req.Scopes == "" {
		return c.Status(400).JSON(fiber.Map{"status": "error", "message": "At least one scope is required"})
	}

	var dup int
	if err := db.Get(&dup, "SELECT COUNT(*) FROM api_keys WHERE name = ?", req.Name); err == nil && dup > 0 {
		return c.Status(400).JSON(fiber.Map{"status": "error", "message": "API key with this name already exists"})
	}

	plaintext, err := generateAPIKey()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Failed to generate key"})
	}

	hashHex, err := middleware.HashKey(plaintext)
	if err != nil {
		return c.Status(503).JSON(fiber.Map{"status": "error", "message": "Server not unlocked"})
	}

	createdAt := time.Now().Format(time.RFC3339)
	expiresAt := ""
	if req.ExpiresDays > 0 {
		expiresAt = time.Now().Add(time.Duration(req.ExpiresDays) * 24 * time.Hour).Format(time.RFC3339)
	}

	res, err := db.Exec(`
		INSERT INTO api_keys (name, key_hash, scopes, created_at, expires_at, last_used_at, last_used_ip)
		VALUES (?, ?, ?, ?, ?, '', '')`,
		req.Name, hashHex, req.Scopes, createdAt, expiresAt)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Failed to save: " + err.Error()})
	}

	id, _ := res.LastInsertId()
	middleware.APIKeyStore.Add(models.APIKey{
		Id:        int(id),
		Name:      req.Name,
		KeyHash:   hashHex,
		Scopes:    req.Scopes,
		CreatedAt: createdAt,
		ExpiresAt: expiresAt,
	})

	slog.Info("APIKeyController: API key created", "name", req.Name, "scopes", req.Scopes, "expires_at", expiresAt)

	return c.Status(200).JSON(fiber.Map{
		"status":  "success",
		"message": "API key created. Save it now — it won't be shown again.",
		"key":     plaintext,
		"name":    req.Name,
	})
}

func generateAPIKey() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return middleware.APIKeyPrefix + base64.RawURLEncoding.EncodeToString(b), nil
}

func fetchAPIKeys(db *sqlx.DB) []models.APIKey {
	keys := []models.APIKey{}
	err := db.Select(&keys, `SELECT id, name, key_hash, scopes,
		COALESCE(created_at, '')    AS created_at,
		COALESCE(expires_at, '')    AS expires_at,
		COALESCE(key_status, 0)     AS key_status,
		COALESCE(last_used_at, '')  AS last_used_at,
		COALESCE(last_used_ip, '')  AS last_used_ip
		FROM api_keys ORDER BY created_at DESC`)
	if err != nil {
		slog.Error("fetchAPIKeys: error", "error", err)
		return keys
	}

	for i := range keys {
		if keys[i].CreatedAt != "" {
			if t, err := time.Parse(time.RFC3339, keys[i].CreatedAt); err == nil {
				keys[i].CreatedAt = t.Format("02.01.2006 15:04:05")
			}
		}
		if keys[i].ExpiresAt != "" {
			if t, err := time.Parse(time.RFC3339, keys[i].ExpiresAt); err == nil {
				keys[i].ExpiresAt = t.Format("02.01.2006 15:04:05")
			}
		}
		if keys[i].LastUsedAt != "" {
			if t, err := time.Parse(time.RFC3339, keys[i].LastUsedAt); err == nil {
				keys[i].LastUsedAt = t.Format("02.01.2006 15:04:05")
			}
		}
	}
	return keys
}
