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
	"strconv"
	"strings"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

// Генерирует ED25519 ключевую пару для пользовательских сертификатов
func GenerateUserED25519KeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ED25519 key pair: %w", err)
	}
	return publicKey, privateKey, nil
}

// Кодирует приватный ключ ED25519 в формат PEM (PKCS8)
func EncodeUserED25519PrivateKeyToPEM(privateKey ed25519.PrivateKey) ([]byte, error) {
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
func EncodeUserED25519PublicKeyToPEM(publicKey ed25519.PublicKey) []byte {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		slog.Error("не удалось закодировать публичный ключ ED25519", slog.Any("error", err))
	}
	publicKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PUBLIC KEY",
			Bytes: publicKeyBytes,
		},
	)
	return publicKeyPEM
}

// standardizeSerialNumber возвращает серийный номер в стандартизированном формате
func UserStandardizeSerialNumberED25519(serialNumber *big.Int) string {
	hexStr := serialNumber.Text(16)
	return strings.ToUpper(hexStr)
}

// Генерирует ED25519 сертификат для пользователей, подписанный промежуточным CA,
// и сохраняет его в базу данных
func GenerateUserED25519Certificate(data *models.UserCertsData, db *sqlx.DB) (certPem, keyPem []byte, err error) {

	// Генерируем новую ED25519 ключевую пару для сертификата
	publicKey, privateKey, err := GenerateUserED25519KeyPair()
	if err != nil {
		return nil, nil, err
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Стандартизируем серийный номер и сохраняем
	data.SerialNumber = UserStandardizeSerialNumberED25519(serialNumber)
	slog.Info("Сгенерирован серийный номер для ED25519 пользовательского сертификата", slog.String("common_name", data.CommonName), slog.String("serial_number", data.SerialNumber))

	extraNames := []pkix.AttributeTypeAndValue{}

	// Добавляем SAN
	dnsNames := []string{data.CommonName}
	// Добавляем альтернативные имена из поля SAN, если они есть
	if data.SAN != "" {
		sanValues := strings.Split(data.SAN, ",")
		for _, san := range sanValues {
			san = strings.TrimSpace(san)
			if san != "" && san != data.CommonName {
				dnsNames = append(dnsNames, san)
			}
		}
	}

	// Добавляем custom OID
	customOID := []int{}
	if data.OID != "" && data.OIDValues != "" {
		lineNumbers := strings.Split(data.OID, ".")
		for _, num := range lineNumbers {
			n, err := strconv.Atoi(num)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to convert OID to number: %w", err)
			}
			customOID = append(customOID, n)
		}
		// Добавляем OID значения
		customOIDValues := []string{}
		oidValues := strings.Split(data.OIDValues, ",")
		for _, oid := range oidValues {
			oid = strings.TrimSpace(oid)
			if oid != "" {
				customOIDValues = append(customOIDValues, oid)
			}
		}

		// если есть кастомный OID, то добавляем в extraNames шаблон email и customOID
		extraNames = append(extraNames, pkix.AttributeTypeAndValue{
			Type:  []int{1, 2, 840, 113549, 1, 9, 1},
			Value: data.Email,
		})
		extraNames = append(extraNames, pkix.AttributeTypeAndValue{
			Type:  customOID,
			Value: strings.Join(customOIDValues, ","),
		})
	} else {
		// если нет кастомного OID, то добавляем в extraNames шаблон email
		extraNames = append(extraNames, pkix.AttributeTypeAndValue{
			Type:  []int{1, 2, 840, 113549, 1, 9, 1},
			Value: data.Email,
		})
	}

	now := time.Now()
	expiry := now.AddDate(0, 0, data.TTL)

	// Создаем шаблон сертификата, поле ExtraNames добавлено выше
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         data.CommonName,
			Country:            []string{data.CountryName},
			Province:           []string{data.StateProvince},
			Locality:           []string{data.LocalityName},
			Organization:       []string{data.Organization},
			OrganizationalUnit: []string{data.OrganizationUnit},
			ExtraNames:         extraNames,
		},
		NotBefore: now,
		NotAfter:  expiry,
		// ED25519 поддерживает только цифровую подпись, НЕ поддерживает шифрование
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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
			return nil, nil, fmt.Errorf("GenerateUserED25519Certificate: failed to extract intermediate CA certificate and key: %w", err)
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

	// Кодируем приватный ключ в PEM (PKCS8 для ED25519)
	keyPEM, err := EncodeUserED25519PrivateKeyToPEM(privateKey)
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
		slog.Warn("Приватный ключ ED25519 сохраняется без шифрования для", slog.String("common_name", data.CommonName), slog.String("reason", "AesSecretKey.Key не установлен"))
		encryptedKey = keyPEM
	}

	// Шифруем password
	encryptedPassword, err := aes.Encrypt([]byte(data.Password), AesSecretKey.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt password: %w", err)
	}
	data.Password = string(encryptedPassword)

	// Вычисляем количество дней до истечения сертификата
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	// Сохраняем сертификат в БД
	tx := db.MustBegin()
	var txCommitted bool
	defer func() {
		// Если произошла паника или транзакция не была зафиксирована, выполняем откат
		if !txCommitted && tx != nil {
			tx.Rollback()
			slog.Error("Транзакция отменена из-за ошибки для", slog.String("common_name", data.CommonName))
		}
	}()

	// Пробуем найти существующую запись для сущности
	var exists bool
	err = tx.Get(&exists, `SELECT EXISTS(SELECT 1 FROM user_certs WHERE common_name = ? AND entity_id = ?)`, data.CommonName, data.EntityId)
	if err != nil {
		tx.Rollback()
		return nil, nil, fmt.Errorf("error checking common_name existence: %v", err)
	}

	if exists {
		// Если запись существует, обновляем её
		// Для ED25519 key_length всегда 256
		_, err = tx.Exec(`UPDATE user_certs SET 
                algorithm = ?, key_length = ?, ttl = ?, recreate = ?,
                common_name = ?, country_name = ?, state_province = ?, locality_name = ?,
                organization = ?, organization_unit = ?, email = ?, password = ?,
                public_key = ?, private_key = ?, cert_create_time = ?, cert_expire_time = ?,
                serial_number = ?, data_revoke = ?, reason_revoke = ?, cert_status = ?, days_left = ?, san = ?, oid = ?, oid_values = ?
            WHERE common_name = ? AND entity_id = ?`,
			data.Algorithm, 256, data.TTL, data.Recreate,
			data.CommonName, data.CountryName, data.StateProvince, data.LocalityName,
			data.Organization, data.OrganizationUnit, data.Email, data.Password,
			string(certPEM), string(encryptedKey), now.Format(time.RFC3339), expiry.Format(time.RFC3339),
			data.SerialNumber, "", "", 0, daysLeft, data.SAN, data.OID, data.OIDValues,
			data.CommonName, data.EntityId)
		if err != nil {
			tx.Rollback()
			return nil, nil, fmt.Errorf("failed to update existing ED25519 certificate in database: %w", err)
		}
		slog.Info("ED25519 сертификат для common_name обновлен в базе данных", slog.String("common_name", data.CommonName), slog.Int("id", data.Id))
	} else {
		// Сертификат не существует, добавляем новый
		// Для ED25519 key_length всегда 256
		_, err = tx.Exec(`INSERT INTO user_certs (
                entity_id, algorithm, key_length, ttl, recreate,
                common_name, country_name, state_province, locality_name,
                organization, organization_unit, email, password,
                public_key, private_key, cert_create_time, cert_expire_time,
                serial_number, data_revoke, reason_revoke, cert_status, days_left, san, oid, oid_values
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			data.EntityId, data.Algorithm, 256, data.TTL, data.Recreate,
			data.CommonName, data.CountryName, data.StateProvince, data.LocalityName,
			data.Organization, data.OrganizationUnit, data.Email, data.Password,
			string(certPEM), string(encryptedKey), now.Format(time.RFC3339), expiry.Format(time.RFC3339),
			data.SerialNumber, "", "", 0, daysLeft, data.SAN, data.OID, data.OIDValues)
		if err != nil {
			tx.Rollback()
			return nil, nil, fmt.Errorf("failed to add new ED25519 certificate to database: %w", err)
		}
		slog.Info("Новый ED25519 сертификат для common_name добавлен в базу данных", slog.String("common_name", data.CommonName))
	}

	// Если все операции прошли успешно, фиксируем транзакцию
	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	txCommitted = true

	if exists {
		slog.Info("Успешно обновлен ED25519 сертификат для common_name", slog.String("common_name", data.CommonName))
	} else {
		slog.Info("Успешно сгенерирован новый ED25519 сертификат для common_name", slog.String("common_name", data.CommonName))
	}
	return certPEM, keyPEM, nil
}

// Пересоздает ED25519 пользовательский сертификат
func RecreateUserED25519Certificate(data *models.UserCertsData, db *sqlx.DB) error {
	// Генерируем новую ED25519 ключевую пару для сертификата
	publicKey, privateKey, err := GenerateUserED25519KeyPair()
	if err != nil {
		return err
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Стандартизируем серийный номер и сохраняем
	data.SerialNumber = UserStandardizeSerialNumberED25519(serialNumber)
	slog.Info("Сгенерирован серийный номер для ED25519 сертификата", slog.String("common_name", data.CommonName), slog.String("serial_number", data.SerialNumber))

	dnsNames := []string{data.CommonName}

	// Добавляем альтернативные имена из поля SAN, если они есть
	if data.SAN != "" {
		sanValues := strings.Split(data.SAN, ",")
		for _, san := range sanValues {
			san = strings.TrimSpace(san)
			if san != "" && san != data.CommonName {
				dnsNames = append(dnsNames, san)
			}
		}
	}

	// Подготавливаем шаблон сертификата
	extraNames := []pkix.AttributeTypeAndValue{}

	// Добавляем custom OID
	customOID := []int{}
	if data.OID != "" && data.OIDValues != "" {
		lineNumbers := strings.Split(data.OID, ".")
		for _, num := range lineNumbers {
			n, err := strconv.Atoi(num)
			if err != nil {
				return fmt.Errorf("failed to convert OID to number: %w", err)
			}
			customOID = append(customOID, n)
		}
		// Добавляем OID значения
		customOIDValues := []string{}
		oidValues := strings.Split(data.OIDValues, ",")
		for _, oid := range oidValues {
			oid = strings.TrimSpace(oid)
			if oid != "" {
				customOIDValues = append(customOIDValues, oid)
			}
		}

		// если есть кастомный OID, то добавляем в extraNames шаблон email и customOID
		extraNames = append(extraNames, pkix.AttributeTypeAndValue{
			Type:  []int{1, 2, 840, 113549, 1, 9, 1},
			Value: data.Email,
		})
		extraNames = append(extraNames, pkix.AttributeTypeAndValue{
			Type:  customOID,
			Value: strings.Join(customOIDValues, ","),
		})
	} else {
		// если нет кастомного OID, то добавляем в extraNames шаблон email
		extraNames = append(extraNames, pkix.AttributeTypeAndValue{
			Type:  []int{1, 2, 840, 113549, 1, 9, 1},
			Value: data.Email,
		})
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
			ExtraNames:         extraNames,
		},
		NotBefore: now,
		NotAfter:  expiry,
		// ED25519 поддерживает только цифровую подпись
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
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
			return fmt.Errorf("RecreateUserED25519Certificate: failed to extract intermediate CA certificate and key: %w", err)
		}
	}
	// Получаем промежуточный CA сертификат и ключ
	subCACert := ExtractCA.SubCAcert
	subCAKey := ExtractCA.SubCAKey
	aes := Aes{}

	// Создаем сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, template, subCACert, publicKey, subCAKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Кодируем сертификат в PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Кодируем приватный ключ в PEM (PKCS8 для ED25519)
	keyPEM, err := EncodeUserED25519PrivateKeyToPEM(privateKey)
	if err != nil {
		return fmt.Errorf("failed to encode private key: %w", err)
	}

	// Шифруем приватный ключ с использованием AesSecretKey.Key
	var encryptedKey []byte
	if len(AesSecretKey.Key) > 0 {
		encryptedKey, err = aes.Encrypt(keyPEM, AesSecretKey.Key)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}
	} else {
		// Если AesSecretKey.Key не доступен, сохраняем ключ без шифрования
		// Это потенциальная проблема безопасности
		slog.Warn("Приватный ключ ED25519 сохраняется без шифрования для", slog.String("common_name", data.CommonName), slog.String("reason", "AesSecretKey.Key не установлен"))
		encryptedKey = keyPEM
	}

	// Шифруем password
	encryptedPassword, err := aes.Encrypt([]byte(data.Password), AesSecretKey.Key)
	if err != nil {
		return fmt.Errorf("failed to encrypt password: %w", err)
	}
	data.Password = string(encryptedPassword)

	// Вычисляем количество дней до истечения сертификата
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	// Сохраняем сертификат в БД
	tx := db.MustBegin()
	var txCommitted bool
	defer func() {
		// Если произошла паника или транзакция не была зафиксирована, выполняем откат
		if !txCommitted && tx != nil {
			tx.Rollback()
			slog.Error("Транзакция отменена из-за ошибки для", slog.String("common_name", data.CommonName))
		}
	}()

	// Для ED25519 key_length всегда 256
	_, err = tx.Exec(`UPDATE user_certs SET 
                algorithm = ?, key_length = ?, ttl = ?, recreate = ?,
                common_name = ?, country_name = ?, state_province = ?, locality_name = ?,
                organization = ?, organization_unit = ?, email = ?, password = ?,
                public_key = ?, private_key = ?, cert_create_time = ?, cert_expire_time = ?,
                serial_number = ?, data_revoke = ?, reason_revoke = ?, cert_status = ?, days_left = ?, san = ?, oid = ?, oid_values = ?
            WHERE id = ?`,
		data.Algorithm, 256, data.TTL, data.Recreate,
		data.CommonName, data.CountryName, data.StateProvince, data.LocalityName,
		data.Organization, data.OrganizationUnit, data.Email, data.Password,
		string(certPEM), string(encryptedKey), now.Format(time.RFC3339), expiry.Format(time.RFC3339),
		data.SerialNumber, "", "", 0, daysLeft, data.SAN, data.OID, data.OIDValues,
		data.Id)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to update ED25519 certificate in database: %w", err)
	}
	slog.Info("ED25519 сертификат для common_name обновлен в базе данных", slog.String("common_name", data.CommonName), slog.Int("id", data.Id))

	// Если все операции прошли успешно, фиксируем транзакцию
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	txCommitted = true

	slog.Info("Успешно обновлен ED25519 сертификат для common_name", slog.String("common_name", data.CommonName), slog.Int("id", data.Id))
	return nil
}
