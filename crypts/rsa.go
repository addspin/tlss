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
	"strings"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
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

// standardizeSerialNumber возвращает серийный номер в стандартизированном формате
// верхний регистр без ведущих нулей
func standardizeSerialNumber(serialNumber *big.Int) string {
	hexStr := serialNumber.Text(16)
	return strings.ToUpper(hexStr)
}

// Генерирует RSA сертификат, подписанный промежуточным CA,
// и сохраняет его в базу данных
func GenerateRSACertificate(data *models.CertsData, db *sqlx.DB) (certPem, keyPem []byte, err error) {

	// Генерируем новую RSA ключевую пару для сертификата
	privateKey, err := rsa.GenerateKey(rand.Reader, data.KeyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("не удалось сгенерировать RSA ключевую пару: %w", err)
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("не удалось сгенерировать серийный номер: %w", err)
	}

	// Стандартизируем серийный номер и сохраняем
	data.SerialNumber = standardizeSerialNumber(serialNumber)
	log.Printf("Сгенерирован серийный номер для сертификата %s: %s", data.Domain, data.SerialNumber)

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
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
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
			return nil, nil, fmt.Errorf("GenerateRSACertificate: не удалось извлечь промежуточный CA сертификат и ключ: %w", err)
		}
	}
	// Получаем промежуточный CA сертификат и ключ
	subCACert := ExtractCA.SubCAcert
	subCAKey := ExtractCA.SubCAKey

	// Создаем сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, template, subCACert, &privateKey.PublicKey, subCAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("не удалось создать сертификат: %w", err)
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
	aes := Aes{}
	// Шифруем приватный ключ с использованием AesSecretKey.Key
	var encryptedKey []byte
	if len(AesSecretKey.Key) > 0 {
		encryptedKey, err = aes.Encrypt(keyPEM, AesSecretKey.Key)
		if err != nil {
			return nil, nil, fmt.Errorf("не удалось зашифровать приватный ключ: %w", err)
		}
	} else {
		// Если AesSecretKey.Key не доступен, сохраняем ключ без шифрования
		// Это потенциальная проблема безопасности
		log.Printf("ВНИМАНИЕ: Приватный ключ сохраняется без шифрования для домена %s, т.к. AesSecretKey.Key не установлен", data.Domain)
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
			log.Printf("Транзакция отменена из-за ошибки для домена %s", data.Domain)
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
		return nil, nil, fmt.Errorf("не удалось добавить новый сертификат в базу данных: %w", err)
	}
	log.Printf("Новый сертификат для домена %s добавлен в базу данных", data.Domain)
	// если не установлен флаг SaveOnServer, комитим транзакцию в базу и завершаем работу
	if !data.SaveOnServer {
		// Фиксируем транзакцию перед возвратом
		if err = tx.Commit(); err != nil {
			return nil, nil, fmt.Errorf("не удалось зафиксировать транзакцию: %w", err)
		}
		txCommitted = true
		return certPEM, keyPEM, nil
	}

	// Если все операции прошли успешно, фиксируем транзакцию
	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("не удалось зафиксировать транзакцию: %w", err)
	}
	txCommitted = true

	log.Printf("Успешно сгенерирован новый RSA сертификат для домена %s", data.Domain)
	return certPEM, keyPEM, nil
}

func RecreateRSACertificate(data *models.CertsData, db *sqlx.DB) (certPem, keyPem []byte, err error) {

	// Генерируем новую RSA ключевую пару для сертификата
	privateKey, err := rsa.GenerateKey(rand.Reader, data.KeyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("не удалось сгенерировать RSA ключевую пару: %w", err)
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("не удалось сгенерировать серийный номер: %w", err)
	}

	// Стандартизируем серийный номер и сохраняем
	data.SerialNumber = standardizeSerialNumber(serialNumber)
	log.Printf("Сгенерирован серийный номер для сертификата %s: %s", data.Domain, data.SerialNumber)

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
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
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
			return nil, nil, fmt.Errorf("RecreateRSACertificate: не удалось извлечь промежуточный CA сертификат и ключ: %w", err)
		}
	}
	// Получаем промежуточный CA сертификат и ключ
	subCACert := ExtractCA.SubCAcert
	subCAKey := ExtractCA.SubCAKey
	aes := Aes{}

	// Создаем сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, template, subCACert, &privateKey.PublicKey, subCAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("не удалось создать сертификат: %w", err)
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
			return nil, nil, fmt.Errorf("не удалось зашифровать приватный ключ: %w", err)
		}
	} else {
		// Если AesSecretKey.Key не доступен, сохраняем ключ без шифрования
		// Это потенциальная проблема безопасности
		log.Printf("ВНИМАНИЕ: Приватный ключ сохраняется без шифрования для домена %s, т.к. AesSecretKey.Key не установлен", data.Domain)
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
			log.Printf("Транзакция отменена из-за ошибки для домена %s", data.Domain)
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
		return nil, nil, fmt.Errorf("не удалось обновить существующий сертификат в базе данных: %w", err)
	}

	log.Printf("Сертификат для домена %s обновлен в базе данных (ID: %d)", data.Domain, data.Id)

	if !data.SaveOnServer {
		// Фиксируем транзакцию перед возвратом
		if err = tx.Commit(); err != nil {
			return nil, nil, fmt.Errorf("не удалось зафиксировать транзакцию: %w", err)
		}
		txCommitted = true
		return certPEM, keyPEM, nil
	}

	// Если все операции прошли успешно, фиксируем транзакцию
	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("не удалось зафиксировать транзакцию: %w", err)
	}
	txCommitted = true

	log.Printf("Успешно сгенерирован новый RSA сертификат для домена %s", data.Domain)
	return certPEM, keyPEM, nil
}
