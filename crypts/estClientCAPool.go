package crypts

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
)

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
