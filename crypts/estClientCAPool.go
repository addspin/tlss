package crypts

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
)

// estCAPoolTTL - как долго переиспользуется собранный пул. Короткий срок
// нужен, чтобы изменения в списке CA (загрузка внешнего CA, отзыв) подхватывались
// без перезапуска. Пересоздание Sub CA сбрасывает кэш немедленно.
const estCAPoolTTL = 30 * time.Second

var estCAPoolCache struct {
	mu      sync.Mutex
	pool    *x509.CertPool
	builtAt time.Time
}

// ESTClientCAPool возвращает пул доверенных CA для проверки клиентских сертификатов
// в mTLS. Результат кэшируется на estCAPoolTTL, поэтому функцию можно вызывать
// на каждое TLS-рукопожатие.
//
// При ошибке сборки возвращается прежний пул, если он есть: отдать пустой пул
// означало бы отвергнуть всех клиентов до следующего успешного обновления.
func ESTClientCAPool(db *sqlx.DB) *x509.CertPool {
	estCAPoolCache.mu.Lock()
	defer estCAPoolCache.mu.Unlock()

	if estCAPoolCache.pool != nil && time.Since(estCAPoolCache.builtAt) < estCAPoolTTL {
		return estCAPoolCache.pool
	}

	pool, err := BuildESTClientCAPool(db)
	if err != nil {
		slog.Error("ESTClientCAPool: failed to rebuild pool, keeping previous", "error", err)
		return estCAPoolCache.pool
	}

	estCAPoolCache.pool = pool
	estCAPoolCache.builtAt = time.Now()
	return pool
}

// ResetESTClientCAPool сбрасывает кэш пула. Вызывается при пересоздании CA,
// чтобы клиенты с новыми сертификатами проходили mTLS сразу, не дожидаясь TTL.
func ResetESTClientCAPool() {
	estCAPoolCache.mu.Lock()
	estCAPoolCache.pool = nil
	estCAPoolCache.builtAt = time.Time{}
	estCAPoolCache.mu.Unlock()
}

// BuildESTClientCAPool собирает пул доверенных CA для верификации клиентских
// сертификатов на EST endpoint. Включает внутренний Sub/Root CA и все внешние CA,
// которые могут выступать издателями (т.е. имеют приватный ключ).
func BuildESTClientCAPool(db *sqlx.DB) (*x509.CertPool, error) {
	pool := x509.NewCertPool()

	internal := []models.CAData{}
	err := db.Select(&internal, "SELECT public_key FROM ca_certs WHERE cert_status = 0")
	if err != nil {
		return nil, fmt.Errorf("load internal CAs: %w", err)
	}
	for _, ca := range internal {
		appendPEM(pool, ca.PublicKey)
	}

	external := []models.CAExtData{}
	err = db.Select(&external, "SELECT public_key FROM ca_certs_ext WHERE cert_status = 0 AND private_key != ''")
	if err == nil {
		for _, ca := range external {
			appendPEM(pool, ca.PublicKey)
		}
	}

	return pool, nil
}

func appendPEM(pool *x509.CertPool, pemData string) {
	rest := []byte(pemData)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			return
		}
		if block.Type == "CERTIFICATE" {
			if cert, err := x509.ParseCertificate(block.Bytes); err == nil {
				pool.AddCert(cert)
			}
		}
	}
}
