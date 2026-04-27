package models

type APIKey struct {
	Id         int    `db:"id" json:"id"`
	Name       string `db:"name" json:"name"`
	KeyHash    string `db:"key_hash" json:"-"`
	Scopes     string `db:"scopes" json:"scopes"`
	CreatedAt  string `db:"created_at" json:"created_at"`
	ExpiresAt  string `db:"expires_at" json:"expires_at"`
	KeyStatus  int    `db:"key_status" json:"key_status"`
	LastUsedAt string `db:"last_used_at" json:"last_used_at"`
	LastUsedIP string `db:"last_used_ip" json:"last_used_ip"`
}

var SchemaAPIKey = `
CREATE TABLE IF NOT EXISTS api_keys (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT UNIQUE NOT NULL,
    key_hash TEXT NOT NULL,
    scopes TEXT,
    created_at TEXT,
    expires_at TEXT,
	key_status INTEGER DEFAULT 0,
    last_used_at TEXT,
    last_used_ip TEXT
);`
