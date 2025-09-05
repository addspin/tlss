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
		return fmt.Errorf("ExtractCA: не удалось получить промежуточный CA: %v", err)
	}
	if subCA.CertStatus != 0 {
		return fmt.Errorf("ExtractCA: промежуточный CA сертификат недоступен")
	}

	// Декодируем промежуточный CA сертификат
	subCACertBlock, _ := pem.Decode([]byte(subCA.PublicKey))
	if subCACertBlock == nil {
		return fmt.Errorf("ExtractCA: не удалось декодировать PEM промежуточного CA сертификата")
	}
	subCAcert, err := x509.ParseCertificate(subCACertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("ExtractCA: не удалось разобрать промежуточный CA сертификат: %w", err)
	}

	// Расшифровываем приватный ключ промежуточного CA
	aes := Aes{}
	decryptedKey, err := aes.Decrypt([]byte(subCA.PrivateKey), AesSecretKey.Key)
	if err != nil {
		return fmt.Errorf("ExtractCA: не удалось расшифровать приватный ключ промежуточного CA: %w", err)
	}

	// Декодируем приватный ключ промежуточного CA
	subCAKeyBlock, _ := pem.Decode(decryptedKey)
	if subCAKeyBlock == nil {
		return fmt.Errorf("ExtractCA: не удалось декодировать PEM приватного ключа промежуточного CA")
	}
	subCAKey, err := x509.ParsePKCS1PrivateKey(subCAKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("ExtractCA: не удалось разобрать приватный ключ промежуточного CA: %w", err)
	}
	e.SubCAcert = subCAcert
	e.SubCAKey = subCAKey

	return nil
}
