package crypts

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log/slog"
	"math/big"
	"strings"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

// Генерирует пару ключей ED25519
func GenerateED25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ED25519 key pair: %w", err)
	}
	return publicKey, privateKey, nil
}

// Кодирует приватный ключ ED25519 в формат PEM
// ED25519 использует PKCS8 формат, в отличие от RSA (PKCS1)
func EncodeED25519PrivateKeyToPEM(privateKey ed25519.PrivateKey) ([]byte, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ED25519 private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	return privateKeyPEM, nil
}

// Кодирует публичный ключ ED25519 в формат PEM
func EncodeED25519PublicKeyToPEM(publicKey ed25519.PublicKey) []byte {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		slog.Error("Failed to encode ED25519 public key", "error", err)
	}
	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	return publicKeyPEM
}

// Генерирует ED25519 сертификат, подписанный промежуточным CA,
// и сохраняет его в базу данных
func GenerateED25519Certificate(data *models.CertsData, db *sqlx.DB) (certPem, keyPem []byte, err error) {

	// Генерируем новую ED25519 ключевую пару для сертификата
	publicKey, privateKey, err := GenerateED25519KeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Стандартизируем серийный номер и сохраняем
	data.SerialNumber = standardizeSerialNumberED25519(serialNumber)
	slog.Info("Generated serial number for ED25519 certificate", "domain", data.Domain, "serial_number", data.SerialNumber)

	// Подготавливаем шаблон сертификата
	dnsNames := []string{data.Domain}
	if data.Wildcard {
		dnsNames = append(dnsNames, "*."+data.Domain)
	}

	// Добавляем альтернативные имена из поля SAN, если они есть
	if data.SAN != "" {
		sanValues := strings.Split(data.SAN, ",")
		for _, san := range sanValues {
			san = strings.TrimSpace(san)
			if san != "" && san != data.Domain && san != "*."+data.Domain {
				dnsNames = append(dnsNames, san)
			}
		}
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
		NotBefore: now,
		NotAfter:  expiry,
		// ED25519 поддерживает только цифровую подпись, НЕ поддерживает шифрование
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		CRLDistributionPoints: []string{
			viper.GetString("CAcrl.crlURL"),
		},
	}

	// Проверяем промежуточный CA сертификат и ключ
	if ExtractCA.SubCAcert == nil || ExtractCA.SubCAKey == nil {
		err = ExtractCA.ExtractSubCA(db)
		if err != nil {
			return nil, nil, fmt.Errorf("GenerateED25519Certificate: failed to extract intermediate CA certificate and key: %w", err)
		}
	}
	// Получаем промежуточный CA сертификат и ключ
	subCACert := ExtractCA.SubCAcert
	subCAKey := ExtractCA.SubCAKey

	// Создаем сертификат (CA может быть RSA, но подписывает ED25519 сертификат)
	certDER, err := x509.CreateCertificate(rand.Reader, template, subCACert, publicKey, subCAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Кодируем сертификат в PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Кодируем приватный ключ в PEM (PKCS8 формат для ED25519)
	keyPEM, err := EncodeED25519PrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	aes := Aes{}
	// Шифруем приватный ключ с использованием AesSecretKey.Key
	var encryptedKey []byte
	if len(AesSecretKey.Key) > 0 {
		encryptedKey, err = aes.Encrypt(keyPEM, AesSecretKey.Key)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}
	} else {
		// Если AesSecretKey.Key не доступен, сохраняем ключ без шифрования
		// Это потенциальная проблема безопасности
		slog.Warn("Private ED25519 key is being saved without encryption for domain", "domain", data.Domain, "reason", "AesSecretKey.Key not set")
		encryptedKey = keyPEM
	}

	// Вычисляем количество дней до истечения сертификата
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	// Сохраняем сертификат в БД
	tx := db.MustBegin()
	var txCommitted bool
	defer func() {
		// Если произошла паника или транзакция не была зафиксирована, выполняем откат
		if !txCommitted && tx != nil {
			tx.Rollback()
			slog.Error("Transaction rolled back due to error for domain", "domain", data.Domain)
		}
	}()

	// Сертификат не существует, добавляем новый
	// Для ED25519 key_length всегда 256 (бит)
	_, err = tx.Exec(`INSERT INTO certs (
			server_id, algorithm, key_length, ttl, domain, wildcard, recreate, save_on_server,
			common_name, country_name, state_province, locality_name, san,
			app_type, organization, organization_unit, email, public_key, private_key,
			cert_create_time, cert_expire_time, serial_number, data_revoke, reason_revoke, cert_status, days_left
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		data.ServerId, data.Algorithm, 256, data.TTL, data.Domain, data.Wildcard, data.Recreate, data.SaveOnServer,
		data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.SAN,
		data.AppType, data.Organization, data.OrganizationUnit, data.Email,
		string(certPEM), string(encryptedKey), now.Format(time.RFC3339), expiry.Format(time.RFC3339), data.SerialNumber, "", "", 0, daysLeft)
	if err != nil {
		tx.Rollback()
		return nil, nil, fmt.Errorf("failed to add new ED25519 certificate to database: %w", err)
	}
	slog.Info("New ED25519 certificate for domain added to database", "domain", data.Domain)

	// если не установлен флаг SaveOnServer, комитим транзакцию в базу и завершаем работу
	if !data.SaveOnServer {
		// Фиксируем транзакцию перед возвратом
		if err = tx.Commit(); err != nil {
			return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
		}
		txCommitted = true
		return certPEM, keyPEM, nil
	}

	// Если все операции прошли успешно, фиксируем транзакцию
	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	txCommitted = true

	slog.Info("Successfully generated new ED25519 certificate for domain", "domain", data.Domain)
	return certPEM, keyPEM, nil
}

// Пересоздает ED25519 сертификат с новыми ключами
func RecreateED25519Certificate(data *models.CertsData, db *sqlx.DB) (certPem, keyPem []byte, err error) {

	// Генерируем новую ED25519 ключевую пару для сертификата
	publicKey, privateKey, err := GenerateED25519KeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Стандартизируем серийный номер и сохраняем
	data.SerialNumber = standardizeSerialNumberED25519(serialNumber)
	slog.Info("Generated serial number for ED25519 certificate", "domain", data.Domain, "serial_number", data.SerialNumber)

	// Подготавливаем шаблон сертификата
	dnsNames := []string{data.Domain}
	if data.Wildcard {
		dnsNames = append(dnsNames, "*."+data.Domain)
	}

	// Добавляем альтернативные имена из поля SAN, если они есть
	if data.SAN != "" {
		sanValues := strings.Split(data.SAN, ",")
		for _, san := range sanValues {
			san = strings.TrimSpace(san)
			if san != "" && san != data.Domain && san != "*."+data.Domain {
				dnsNames = append(dnsNames, san)
			}
		}
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
		NotBefore: now,
		NotAfter:  expiry,
		// ED25519 поддерживает только цифровую подпись
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		CRLDistributionPoints: []string{
			viper.GetString("SubCAcrl.crlURL"),
		},
	}

	// Проверяем промежуточный CA сертификат и ключ
	if ExtractCA.SubCAcert == nil || ExtractCA.SubCAKey == nil {
		err = ExtractCA.ExtractSubCA(db)
		if err != nil {
			return nil, nil, fmt.Errorf("RecreateED25519Certificate: failed to extract intermediate CA certificate and key: %w", err)
		}
	}
	// Получаем промежуточный CA сертификат и ключ
	subCACert := ExtractCA.SubCAcert
	subCAKey := ExtractCA.SubCAKey
	aes := Aes{}

	// Создаем сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, template, subCACert, publicKey, subCAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Кодируем сертификат в PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Кодируем приватный ключ в PEM (PKCS8 формат для ED25519)
	keyPEM, err := EncodeED25519PrivateKeyToPEM(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode private key: %w", err)
	}

	// Шифруем приватный ключ с использованием AesSecretKey.Key
	var encryptedKey []byte
	if len(AesSecretKey.Key) > 0 {
		encryptedKey, err = aes.Encrypt(keyPEM, AesSecretKey.Key)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}
	} else {
		// Если AesSecretKey.Key не доступен, сохраняем ключ без шифрования
		// Это потенциальная проблема безопасности
		slog.Warn("Private ED25519 key is being saved without encryption for domain", "domain", data.Domain, "reason", "AesSecretKey.Key not set")
		encryptedKey = keyPEM
	}

	// Вычисляем количество дней до истечения сертификата
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	// Сохраняем сертификат в БД
	tx := db.MustBegin()
	var txCommitted bool
	defer func() {
		// Если произошла паника или транзакция не была зафиксирована, выполняем откат
		if !txCommitted && tx != nil {
			tx.Rollback()
			slog.Error("Transaction rolled back due to error for domain", "domain", data.Domain)
		}
	}()

	// Обновляем существующий сертификат
	_, err = tx.Exec(`UPDATE certs SET
	            algorithm = ?, key_length = ?, ttl = ?, wildcard = ?, recreate = ?, save_on_server = ?,
	            common_name = ?, country_name = ?, state_province = ?, locality_name = ?, san = ?,
	            app_type = ?, organization = ?, organization_unit = ?, email = ?,
	            public_key = ?, private_key = ?, cert_create_time = ?, cert_expire_time = ?,
	            serial_number = ?, data_revoke = ?, reason_revoke = ?, cert_status = ?, days_left = ?
	        WHERE domain = ? AND server_id = ?`,
		data.Algorithm, 256, data.TTL, data.Wildcard, data.Recreate, data.SaveOnServer,
		data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.SAN,
		data.AppType, data.Organization, data.OrganizationUnit, data.Email,
		string(certPEM), string(encryptedKey), now.Format(time.RFC3339), expiry.Format(time.RFC3339),
		data.SerialNumber, "", "", 0, daysLeft,
		data.Domain, data.ServerId)
	if err != nil {
		tx.Rollback()
		return nil, nil, fmt.Errorf("failed to update existing ED25519 certificate in database: %w", err)
	}

	slog.Info("ED25519 certificate for domain updated in database", "domain", data.Domain, "id", data.Id)

	if !data.SaveOnServer {
		// Фиксируем транзакцию перед возвратом
		if err = tx.Commit(); err != nil {
			return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
		}
		txCommitted = true
		return certPEM, keyPEM, nil
	}

	// Если все операции прошли успешно, фиксируем транзакцию
	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	txCommitted = true

	slog.Info("Successfully recreated ED25519 certificate for domain", "domain", data.Domain)
	return certPEM, keyPEM, nil
}

// standardizeSerialNumberED25519 возвращает серийный номер в стандартизированном формате
// верхний регистр без ведущих нулей
func standardizeSerialNumberED25519(serialNumber *big.Int) string {
	hexStr := serialNumber.Text(16)
	return strings.ToUpper(hexStr)
}

// CreateAndSignED25519Cert - упрощенная функция для создания и подписи ED25519 сертификата
// Оставлена для обратной совместимости
func CreateAndSignED25519Cert(caCert *x509.Certificate, caPrivKey interface{}) (*x509.Certificate, ed25519.PrivateKey, error) {
	// Генерируем пару ключей ED25519
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Создаем шаблон сертификата
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "ED25519 Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Подписываем сертификат с помощью CA (может быть RSA или ED25519)
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	// Парсим созданный сертификат
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}
