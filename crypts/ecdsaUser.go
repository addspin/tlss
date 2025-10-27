package crypts

import (
	"crypto/ecdsa"
	"crypto/elliptic"
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

// Генерирует ECDSA ключевую пару для пользовательских сертификатов
func GenerateUserECDSAKeyPair(keyLength int) (*ecdsa.PrivateKey, error) {
	var curve elliptic.Curve
	switch keyLength {
	case 224:
		curve = elliptic.P224()
	case 256:
		curve = elliptic.P256()
	case 384:
		curve = elliptic.P384()
	case 521:
		curve = elliptic.P521()
	default:
		curve = elliptic.P256() // По умолчанию P-256
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}
	return privateKey, nil
}

// Кодирует приватный ключ ECDSA в формат PEM
func EncodeUserECDSAPrivateKeyToPEM(privateKey *ecdsa.PrivateKey) ([]byte, error) {
	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "EC PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	return privateKeyPEM, nil
}

// Кодирует публичный ключ ECDSA в формат PEM
func EncodeUserECDSAPublicKeyToPEM(publicKey *ecdsa.PublicKey) []byte {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		slog.Error("Failed to encode ECDSA public key", slog.Any("error", err))
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
func UserStandardizeSerialNumberECDSA(serialNumber *big.Int) string {
	hexStr := serialNumber.Text(16)
	return strings.ToUpper(hexStr)
}

// Генерирует ECDSA сертификат для пользователей, подписанный промежуточным CA,
// и сохраняет его в базу данных
func GenerateUserECDSACertificate(data *models.UserCertsData, db *sqlx.DB) (certPem, keyPem []byte, err error) {

	// Генерируем новую ECDSA ключевую пару для сертификата
	privateKey, err := GenerateUserECDSAKeyPair(data.KeyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Стандартизируем серийный номер и сохраняем
	data.SerialNumber = UserStandardizeSerialNumberECDSA(serialNumber)
	slog.Info("Generated serial number for ECDSA user certificate", slog.String("common_name", data.CommonName), slog.String("serial_number", data.SerialNumber))

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
		NotBefore:             now,
		NotAfter:              expiry,
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
			return nil, nil, fmt.Errorf("GenerateUserECDSACertificate: failed to extract intermediate CA certificate and key: %w", err)
		}
	}
	// Получаем промежуточный CA сертификат и ключ
	subCACert := ExtractCA.SubCAcert
	subCAKey := ExtractCA.SubCAKey
	aes := Aes{}

	// Создаем сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, template, subCACert, &privateKey.PublicKey, subCAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Кодируем сертификат в PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Кодируем приватный ключ в PEM
	keyPEM, err := EncodeUserECDSAPrivateKeyToPEM(privateKey)
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
		slog.Warn("Private ECDSA key is being saved without encryption for", slog.String("common_name", data.CommonName), slog.String("reason", "AesSecretKey.Key not set"))
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
			slog.Error("Transaction cancelled due to error for", slog.String("common_name", data.CommonName))
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
		_, err = tx.Exec(`UPDATE user_certs SET 
                algorithm = ?, key_length = ?, ttl = ?, recreate = ?,
                common_name = ?, country_name = ?, state_province = ?, locality_name = ?,
                organization = ?, organization_unit = ?, email = ?, password = ?,
                public_key = ?, private_key = ?, cert_create_time = ?, cert_expire_time = ?,
                serial_number = ?, data_revoke = ?, reason_revoke = ?, cert_status = ?, days_left = ?, san = ?, oid = ?, oid_values = ?
            WHERE common_name = ? AND entity_id = ?`,
			data.Algorithm, data.KeyLength, data.TTL, data.Recreate,
			data.CommonName, data.CountryName, data.StateProvince, data.LocalityName,
			data.Organization, data.OrganizationUnit, data.Email, data.Password,
			string(certPEM), string(encryptedKey), now.Format(time.RFC3339), expiry.Format(time.RFC3339),
			data.SerialNumber, "", "", 0, daysLeft, data.SAN, data.OID, data.OIDValues,
			data.CommonName, data.EntityId)
		if err != nil {
			tx.Rollback()
			return nil, nil, fmt.Errorf("failed to update existing ECDSA certificate in database: %w", err)
		}
		slog.Info("ECDSA certificate for common_name updated in database", slog.String("common_name", data.CommonName), slog.Int("id", data.Id))
	} else {
		// Сертификат не существует, добавляем новый
		_, err = tx.Exec(`INSERT INTO user_certs (
                entity_id, algorithm, key_length, ttl, recreate,
                common_name, country_name, state_province, locality_name,
                organization, organization_unit, email, password,
                public_key, private_key, cert_create_time, cert_expire_time,
                serial_number, data_revoke, reason_revoke, cert_status, days_left, san, oid, oid_values
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			data.EntityId, data.Algorithm, data.KeyLength, data.TTL, data.Recreate,
			data.CommonName, data.CountryName, data.StateProvince, data.LocalityName,
			data.Organization, data.OrganizationUnit, data.Email, data.Password,
			string(certPEM), string(encryptedKey), now.Format(time.RFC3339), expiry.Format(time.RFC3339),
			data.SerialNumber, "", "", 0, daysLeft, data.SAN, data.OID, data.OIDValues)
		if err != nil {
			tx.Rollback()
			return nil, nil, fmt.Errorf("failed to add new ECDSA certificate to database: %w", err)
		}
		slog.Info("New ECDSA certificate for common_name added to database", slog.String("common_name", data.CommonName))
	}

	// Если все операции прошли успешно, фиксируем транзакцию
	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	txCommitted = true

	if exists {
		slog.Info("Successfully updated ECDSA certificate for common_name", slog.String("common_name", data.CommonName))
	} else {
		slog.Info("Successfully generated new ECDSA certificate for common_name", slog.String("common_name", data.CommonName))
	}
	return certPEM, keyPEM, nil
}

// Пересоздает ECDSA пользовательский сертификат
func RecreateUserECDSACertificate(data *models.UserCertsData, db *sqlx.DB) error {
	// Генерируем новую ECDSA ключевую пару для сертификата
	privateKey, err := GenerateUserECDSAKeyPair(data.KeyLength)
	if err != nil {
		return err
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Стандартизируем серийный номер и сохраняем
	data.SerialNumber = UserStandardizeSerialNumberECDSA(serialNumber)
	slog.Info("Generated serial number for ECDSA certificate", slog.String("common_name", data.CommonName), slog.String("serial_number", data.SerialNumber))

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
		NotBefore:             now,
		NotAfter:              expiry,
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
			return fmt.Errorf("RecreateUserECDSACertificate: failed to extract intermediate CA certificate and key: %w", err)
		}
	}
	// Получаем промежуточный CA сертификат и ключ
	subCACert := ExtractCA.SubCAcert
	subCAKey := ExtractCA.SubCAKey
	aes := Aes{}

	// Создаем сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, template, subCACert, &privateKey.PublicKey, subCAKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Кодируем сертификат в PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	// Кодируем приватный ключ в PEM
	keyPEM, err := EncodeUserECDSAPrivateKeyToPEM(privateKey)
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
		slog.Warn("Private ECDSA key is being saved without encryption for", slog.String("common_name", data.CommonName), slog.String("reason", "AesSecretKey.Key not set"))
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

	_, err = tx.Exec(`UPDATE user_certs SET 
                algorithm = ?, key_length = ?, ttl = ?, recreate = ?,
                common_name = ?, country_name = ?, state_province = ?, locality_name = ?,
                organization = ?, organization_unit = ?, email = ?, password = ?,
                public_key = ?, private_key = ?, cert_create_time = ?, cert_expire_time = ?,
                serial_number = ?, data_revoke = ?, reason_revoke = ?, cert_status = ?, days_left = ?, san = ?, oid = ?, oid_values = ?
            WHERE id = ?`,
		data.Algorithm, data.KeyLength, data.TTL, data.Recreate,
		data.CommonName, data.CountryName, data.StateProvince, data.LocalityName,
		data.Organization, data.OrganizationUnit, data.Email, data.Password,
		string(certPEM), string(encryptedKey), now.Format(time.RFC3339), expiry.Format(time.RFC3339),
		data.SerialNumber, "", "", 0, daysLeft, data.SAN, data.OID, data.OIDValues,
		data.Id)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to update ECDSA certificate in database: %w", err)
	}
	slog.Info("ECDSA certificate for common_name updated in database", slog.String("common_name", data.CommonName), slog.Int("id", data.Id))

	// Если все операции прошли успешно, фиксируем транзакцию
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	txCommitted = true

	slog.Info("Successfully updated ECDSA certificate for common_name", slog.String("common_name", data.CommonName), slog.Int("id", data.Id))
	return nil
}
