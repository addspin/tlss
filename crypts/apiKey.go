package crypts

import (
	"crypto/rand"
	"encoding/base64"
	"sync"
)

var (
	internalAPIKey string
	once           sync.Once
)

// GetInternalAPIKey возвращает API ключ, создавая его только при первом вызове
func GetInternalAPIKey() string {
	once.Do(func() {
		// Генерируем ключ только один раз при первом вызове
		key := make([]byte, 32)
		rand.Read(key)
		internalAPIKey = base64.StdEncoding.EncodeToString(key)
	})
	return internalAPIKey
}
