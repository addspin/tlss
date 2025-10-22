package crypts

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
)

type ca struct {
	SubCAcert *x509.Certificate
	SubCAKey  *rsa.PrivateKey
	// rootCAcert *x509.Certificate
	// rootCAKey  *rsa.PrivateKey
}

var ExtractCA = ca{}

func (e *ca) ExtractSubCA(db *sqlx.DB) error {
	// Получаем промежуточный CA сертификат из базы данных
	var subCA models.CAData
	err := db.Get(&subCA, "SELECT * FROM ca_certs WHERE type_ca = 'Sub' AND cert_status = 0")
	if err != nil {
		return fmt.Errorf("ExtractCA: failed to get intermediate CA: %v", err)
	}
	if subCA.CertStatus != 0 {
		return fmt.Errorf("ExtractCA: intermediate CA certificate is unavailable")
	}

	// Декодируем промежуточный CA сертификат
	subCACertBlock, _ := pem.Decode([]byte(subCA.PublicKey))
	if subCACertBlock == nil {
		return fmt.Errorf("ExtractCA: failed to decode intermediate CA certificate PEM")
	}
	subCAcert, err := x509.ParseCertificate(subCACertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("ExtractCA: failed to parse intermediate CA certificate: %w", err)
	}

	// Расшифровываем приватный ключ промежуточного CA
	aes := Aes{}
	decryptedKey, err := aes.Decrypt([]byte(subCA.PrivateKey), AesSecretKey.Key)
	if err != nil {
		return fmt.Errorf("ExtractCA: failed to decrypt intermediate CA private key: %w", err)
	}

	// Декодируем приватный ключ промежуточного CA
	subCAKeyBlock, _ := pem.Decode(decryptedKey)
	if subCAKeyBlock == nil {
		return fmt.Errorf("ExtractCA: failed to decode intermediate CA private key PEM")
	}
	subCAKey, err := x509.ParsePKCS1PrivateKey(subCAKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("ExtractCA: failed to parse intermediate CA private key: %w", err)
	}
	e.SubCAcert = subCAcert
	e.SubCAKey = subCAKey

	return nil
}
