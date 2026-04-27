package middleware

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
)

// APIKeyStore — потокобезопасное in-memory хранилище API ключей.
// Ключи мапы — HMAC-SHA256 от plaintext-ключа в hex; значения — записи из api_keys.
// Используется для O(1) проверки в APIKeyAuth вместо bcrypt-перебора.
var APIKeyStore = &apiKeyStore{m: make(map[string]models.APIKey)}

type apiKeyStore struct {
	mu sync.RWMutex
	m  map[string]models.APIKey
}

// HashKey считает HMAC-SHA256(AesSecretKey, plaintext) и возвращает hex-строку.
// Возвращает ошибку, если серверный секрет ещё не разблокирован (пользователь не залогинен).
func HashKey(plaintext string) (string, error) {
	secret := crypts.AesSecretKey.Key
	if len(secret) == 0 {
		return "", errors.New("server secret not initialized")
	}
	h := hmac.New(sha256.New, secret)
	h.Write([]byte(plaintext))
	return hex.EncodeToString(h.Sum(nil)), nil
}

// Load перезаполняет хранилище из БД. Безопасно вызывать при старте и в любой момент.
func (s *apiKeyStore) Load(db *sqlx.DB) error {
	keys := []models.APIKey{}
	err := db.Select(&keys, `SELECT id, name, key_hash, scopes,
		COALESCE(created_at, '')   AS created_at,
		COALESCE(expires_at, '')   AS expires_at,
		COALESCE(last_used_at, '') AS last_used_at,
		COALESCE(last_used_ip, '') AS last_used_ip
		FROM api_keys`)
	if err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.m = make(map[string]models.APIKey, len(keys))
	for _, k := range keys {
		s.m[k.KeyHash] = k
	}
	return nil
}

// Get возвращает запись ключа по hex-HMAC; ok=false если не найдено.
func (s *apiKeyStore) Get(hashHex string) (models.APIKey, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	k, ok := s.m[hashHex]
	return k, ok
}

// Add регистрирует новый ключ в хранилище.
func (s *apiKeyStore) Add(k models.APIKey) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.m[k.KeyHash] = k
}

// DeleteByID удаляет запись по id.
func (s *apiKeyStore) DeleteByID(id int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, v := range s.m {
		if v.Id == id {
			delete(s.m, k)
			return
		}
	}
}

// UpdateLastUsed обновляет поля last_used_at/last_used_ip в in-memory записи.
func (s *apiKeyStore) UpdateLastUsed(id int, ts, ip string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for hash, v := range s.m {
		if v.Id == id {
			v.LastUsedAt = ts
			v.LastUsedIP = ip
			s.m[hash] = v
			return
		}
	}
}
