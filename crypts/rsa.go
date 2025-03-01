package crypts

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
)

// Генерирует RSA ключевую пару
func GenerateRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать RSA ключевую пару: %w", err)
	}
	return privateKey, nil
}

// Кодирует приватный ключ RSA в формат PEM
func EncodeRSAPrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	return privateKeyPEM
}

// Кодирует публичный ключ RSA в формат PEM
func EncodeRSAPublicKeyToPEM(publicKey *rsa.PublicKey) []byte {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		log.Fatalf("не удалось закодировать публичный ключ: %v", err)
	}
	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	return publicKeyPEM
}

// Генерирует RSA сертификат, подписанный промежуточным CA,
// и сохраняет его в базу данных
func GenerateRSACertificate(data *models.CertsData, db *sqlx.DB) error {

	// Получаем промежуточный CA сертификат из базы данных
	var subCA models.SubCA
	err := db.Get(&subCA, "SELECT * FROM sub_ca_tlss WHERE id = 1")
	if err != nil {
		return fmt.Errorf("не удалось получить промежуточный CA: %w", err)
	}

	if !subCA.State {
		return fmt.Errorf("промежуточный CA сертификат недоступен")
	}

	// Декодируем промежуточный CA сертификат
	subCACertBlock, _ := pem.Decode([]byte(subCA.PublicKey))
	if subCACertBlock == nil {
		return fmt.Errorf("не удалось декодировать PEM промежуточного CA сертификата")
	}
	subCACert, err := x509.ParseCertificate(subCACertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("не удалось разобрать промежуточный CA сертификат: %w", err)
	}

	// Расшифровываем приватный ключ промежуточного CA
	aes := Aes{}
	decryptedKey, err := aes.Decrypt([]byte(subCA.PrivateKey), AesSecretKey.Key)
	if err != nil {
		return fmt.Errorf("не удалось расшифровать приватный ключ промежуточного CA: %w", err)
	}

	// Декодируем приватный ключ промежуточного CA
	subCAKeyBlock, _ := pem.Decode(decryptedKey)
	if subCAKeyBlock == nil {
		return fmt.Errorf("не удалось декодировать PEM приватного ключа промежуточного CA")
	}
	subCAKey, err := x509.ParsePKCS1PrivateKey(subCAKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("не удалось разобрать приватный ключ промежуточного CA: %w", err)
	}

	// Генерируем новую RSA ключевую пару для сертификата
	privateKey, err := rsa.GenerateKey(rand.Reader, data.KeyLength)
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать RSA ключевую пару: %w", err)
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать серийный номер: %w", err)
	}

	// Подготавливаем шаблон сертификата
	dnsNames := []string{data.Domain}
	if data.Wildcard {
		dnsNames = append(dnsNames, "*."+data.Domain)
	}

	now := time.Now()
	expiry := now.AddDate(0, 0, data.TTL)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         data.CommonName,
			Country:            []string{data.CountryName},
			Province:           []string{data.StateProvince},
			Locality:           []string{data.LocalityName},
			Organization:       []string{data.Organization},
			OrganizationalUnit: []string{data.OrganizationUnit},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{1, 2, 840, 113549, 1, 9, 1},
					Value: data.Email,
				},
			},
		},
		NotBefore:             now,
		NotAfter:              expiry,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
	}

	// Создаем сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, template, subCACert, &privateKey.PublicKey, subCAKey)
	if err != nil {
		return fmt.Errorf("не удалось создать сертификат: %w", err)
	}

	// Кодируем сертификат и приватный ключ в PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Шифруем приватный ключ с использованием AesSecretKey.Key
	var encryptedKey []byte
	if len(AesSecretKey.Key) > 0 {
		encryptedKey, err = aes.Encrypt(keyPEM, AesSecretKey.Key)
		if err != nil {
			return fmt.Errorf("не удалось зашифровать приватный ключ: %w", err)
		}
	} else {
		// Если AesSecretKey.Key не доступен, сохраняем ключ без шифрования
		// Это потенциальная проблема безопасности
		log.Printf("ВНИМАНИЕ: Приватный ключ сохраняется без шифрования для домена %s, т.к. AesSecretKey.Key не установлен", data.Domain)
		encryptedKey = keyPEM
	}

	// Сохраняем сертификат в базу данных (без сохранения пароля)
	_, err = db.Exec(`
		INSERT INTO certs (
			server_id, algorithm, key_length, ttl, domain, wildcard, recreate,
			common_name, country_name, state_province, locality_name, organization, organization_unit, email,
			public_key, private_key, cert_create_time, cert_expire_time
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		data.ServerId, data.Algorithm, data.KeyLength, data.TTL, data.Domain, data.Wildcard, data.Recreate,
		data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.Organization, data.OrganizationUnit, data.Email,
		string(certPEM), string(encryptedKey), now.Format("02.01.2006 15:04:05"), expiry.Format("02.01.2006 15:04:05"),
	)
	if err != nil {
		return fmt.Errorf("не удалось сохранить сертификат в базу данных: %w", err)
	}

	log.Printf("Успешно сгенерирован RSA сертификат для домена %s", data.Domain)
	return nil
}
