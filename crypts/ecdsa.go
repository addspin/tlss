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
	"strings"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

// Генерирует ECDSA ключевую пару
func GenerateECDSAKeyPair(keyLength int) (*ecdsa.PrivateKey, error) {
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
func EncodeECDSAPrivateKeyToPEM(privateKey *ecdsa.PrivateKey) ([]byte, error) {
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
func EncodeECDSAPublicKeyToPEM(publicKey *ecdsa.PublicKey) []byte {
	publicKeyBytes, err := x509.MarshalPKIXPublicKey(publicKey)
	if err != nil {
		slog.Error("Failed to encode ECDSA public key", "error", err)
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
// верхний регистр без ведущих нулей
func standardizeSerialNumberECDSA(serialNumber *big.Int) string {
	hexStr := serialNumber.Text(16)
	return strings.ToUpper(hexStr)
}

// Генерирует ECDSA сертификат, подписанный промежуточным CA,
// и сохраняет его в базу данных
func GenerateECDSACertificate(data *models.CertsData, db *sqlx.DB) (certPem, keyPem []byte, err error) {

	// Генерируем новую ECDSA ключевую пару для сертификата
	privateKey, err := GenerateECDSAKeyPair(data.KeyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Стандартизируем серийный номер и сохраняем
	data.SerialNumber = standardizeSerialNumberECDSA(serialNumber)
	slog.Info("Generated serial number for certificate", "domain", data.Domain, "serial_number", data.SerialNumber)

	// Подготавливаем шаблон сертификата
	//dnsNames = SAN

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
		NotBefore:             now,
		NotAfter:              expiry,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		CRLDistributionPoints: []string{
			viper.GetString("CAcrl.crlURL"),
		},
	}

	// Проверяем промежуточный CA сертификат и ключ (используем существующий RSA CA)
	if ExtractCA.SubCAcert == nil || ExtractCA.SubCAKey == nil {
		err = ExtractCA.ExtractSubCA(db)
		if err != nil {
			return nil, nil, fmt.Errorf("GenerateECDSACertificate: failed to extract intermediate CA certificate and key: %w", err)
		}
	}
	// Получаем промежуточный CA сертификат и ключ
	subCACert := ExtractCA.SubCAcert
	subCAKey := ExtractCA.SubCAKey

	// Создаем сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, template, subCACert, &privateKey.PublicKey, subCAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Кодируем сертификат и приватный ключ в PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

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
		slog.Warn("Private key is being saved without encryption for domain", "domain", data.Domain, "reason", "AesSecretKey.Key not set")
		encryptedKey = keyPEM
	}

	// Вычисляем количество дней до истечения сертификата
	daysLeft := int(expiry.Sub(now).Hours() / 24)
	// data.DaysLeft = daysLeft

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
	_, err = tx.Exec(`INSERT INTO certs (
			server_id, algorithm, key_length, ttl, domain, wildcard, recreate, save_on_server,
			common_name, country_name, state_province, locality_name, san,
			app_type, organization, organization_unit, email, public_key, private_key,
			cert_create_time, cert_expire_time, serial_number, data_revoke, reason_revoke, cert_status, days_left
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		data.ServerId, data.Algorithm, data.KeyLength, data.TTL, data.Domain, data.Wildcard, data.Recreate, data.SaveOnServer,
		data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.SAN,
		data.AppType, data.Organization, data.OrganizationUnit, data.Email,
		string(certPEM), string(encryptedKey), now.Format(time.RFC3339), expiry.Format(time.RFC3339), data.SerialNumber, "", "", 0, daysLeft)
	if err != nil {
		tx.Rollback()
		return nil, nil, fmt.Errorf("failed to add new certificate to database: %w", err)
	}
	slog.Info("New certificate for domain added to database", "domain", data.Domain)
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

	slog.Info("Successfully generated new ECDSA certificate for domain", "domain", data.Domain)
	return certPEM, keyPEM, nil
}

func RecreateECDSACertificate(data *models.CertsData, db *sqlx.DB) (certPem, keyPem []byte, err error) {

	// Генерируем новую ECDSA ключевую пару для сертификата
	privateKey, err := GenerateECDSAKeyPair(data.KeyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Стандартизируем серийный номер и сохраняем
	data.SerialNumber = standardizeSerialNumberECDSA(serialNumber)
	slog.Info("Generated serial number for certificate", "domain", data.Domain, "serial_number", data.SerialNumber)

	// Подготавливаем шаблон сертификата
	//dnsNames = SAN

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
		NotBefore:             now,
		NotAfter:              expiry,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		CRLDistributionPoints: []string{
			viper.GetString("SubCAcrl.crlURL"),
		},
	}
	// Проверяем промежуточный CA сертификат и ключ (используем существующий RSA CA)
	if ExtractCA.SubCAcert == nil || ExtractCA.SubCAKey == nil {
		err = ExtractCA.ExtractSubCA(db)
		if err != nil {
			return nil, nil, fmt.Errorf("RecreateECDSACertificate: failed to extract intermediate CA certificate and key: %w", err)
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

	// Кодируем сертификат и приватный ключ в PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	privateKeyBytes, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal ECDSA private key: %w", err)
	}

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: privateKeyBytes,
	})

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
		slog.Warn("Private key is being saved without encryption for domain", "domain", data.Domain, "reason", "AesSecretKey.Key not set")
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

	_, err = tx.Exec(`UPDATE certs SET
	            algorithm = ?, key_length = ?, ttl = ?, wildcard = ?, recreate = ?, save_on_server = ?,
	            common_name = ?, country_name = ?, state_province = ?, locality_name = ?, san = ?,
	            app_type = ?, organization = ?, organization_unit = ?, email = ?,
	            public_key = ?, private_key = ?, cert_create_time = ?, cert_expire_time = ?,
	            serial_number = ?, data_revoke = ?, reason_revoke = ?, cert_status = ?, days_left = ?
	        WHERE domain = ? AND server_id = ?`,
		data.Algorithm, data.KeyLength, data.TTL, data.Wildcard, data.Recreate, data.SaveOnServer,
		data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.SAN,
		data.AppType, data.Organization, data.OrganizationUnit, data.Email,
		string(certPEM), string(encryptedKey), now.Format(time.RFC3339), expiry.Format(time.RFC3339),
		data.SerialNumber, "", "", 0, daysLeft,
		data.Domain, data.ServerId)
	if err != nil {
		tx.Rollback()
		return nil, nil, fmt.Errorf("failed to update existing certificate in database: %w", err)
	}

	slog.Info("Certificate for domain updated in database", "domain", data.Domain, "id", data.Id)

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

	slog.Info("Successfully generated new ECDSA certificate for domain", "domain", data.Domain)
	return certPEM, keyPEM, nil
}
