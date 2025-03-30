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
	"os"
	"os/exec"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
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

// Генерирует RSA сертификат, подписанный промежуточным CA,
// и сохраняет его в базу данных
func GenerateRSACertificate(data *models.Certs, db *sqlx.DB) error {

	// Получаем промежуточный CA сертификат из базы данных
	var subCA models.SubCA
	err := db.Get(&subCA, "SELECT * FROM sub_ca_tlss WHERE id = 1")
	if err != nil {
		return fmt.Errorf("не удалось получить промежуточный CA: %w", err)
	}

	if subCA.SubCAStatus != 0 {
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

	// Присваиваем серийный номер структуре data как строку в hex формате
	data.SerialNumber = fmt.Sprintf("%X", serialNumber)

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
		CRLDistributionPoints: []string{
			viper.GetString("crl.crlURL"),
		},
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

	// Начинаем транзакцию
	tx, err := db.Beginx()
	if err != nil {
		return fmt.Errorf("не удалось начать транзакцию: %w", err)
	}

	// Отложенная функция для отката транзакции в случае ошибки
	defer func() {
		if err != nil {
			tx.Rollback()
			log.Printf("Транзакция отменена из-за ошибки: %v", err)
		}
	}()

	// Вычисляем количество дней до истечения сертификата
	daysLeft := int(expiry.Sub(now).Hours() / 24)
	data.DaysLeft = daysLeft

	// Проверяем существование сертификата с такими же domain, wildcard и server_id
	var existingCerts []models.Certs

	err = tx.Select(&existingCerts, `
		SELECT id FROM certs 
		WHERE domain = ? AND wildcard = ? AND server_id = ?
	`, data.Domain, data.Wildcard, data.ServerId)

	if err != nil {
		return fmt.Errorf("ошибка при проверке существования сертификата: %w", err)
	}

	certExists := len(existingCerts) > 0

	if certExists {
		// Сертификат существует, обновляем его
		data.Id = existingCerts[0].Id // Получаем ID из существующего сертификата
		_, err = tx.Exec(`
			UPDATE certs SET 
				algorithm = ?, key_length = ?, ttl = ?, recreate = ?,
				common_name = ?, country_name = ?, state_province = ?, locality_name = ?, 
				organization = ?, organization_unit = ?, email = ?,
				public_key = ?, private_key = ?, cert_create_time = ?, cert_expire_time = ?, 
				serial_number = ?, data_revoke = ?, reason_revoke = ?, cert_status = ?, days_left = ?
			WHERE id = ?
		`,
			data.Algorithm, data.KeyLength, data.TTL, data.Recreate,
			data.CommonName, data.CountryName, data.StateProvince, data.LocalityName,
			data.Organization, data.OrganizationUnit, data.Email,
			string(certPEM), string(encryptedKey), now.Format("02.01.2006 15:04:05"), expiry.Format("02.01.2006 15:04:05"),
			data.SerialNumber, "", "", 0, data.DaysLeft,
			data.Id,
		)
		if err != nil {
			return fmt.Errorf("не удалось обновить существующий сертификат в базе данных: %w", err)
		}
		log.Printf("Сертификат для домена %s обновлен в базе данных (ID: %d)", data.Domain, data.Id)
	} else {
		// Сертификат не существует, добавляем новый
		_, err = tx.Exec(`
			INSERT INTO certs (
				server_id, algorithm, key_length, ttl, domain, wildcard, recreate,
				common_name, country_name, state_province, locality_name, organization, organization_unit, email,
				public_key, private_key, cert_create_time, cert_expire_time, serial_number, data_revoke, reason_revoke, cert_status, days_left
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		`,
			data.ServerId, data.Algorithm, data.KeyLength, data.TTL, data.Domain, data.Wildcard, data.Recreate,
			data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.Organization, data.OrganizationUnit, data.Email,
			string(certPEM), string(encryptedKey), now.Format("02.01.2006 15:04:05"), expiry.Format("02.01.2006 15:04:05"), data.SerialNumber, "", "", 0, data.DaysLeft,
		)
		if err != nil {
			return fmt.Errorf("не удалось добавить новый сертификат в базу данных: %w", err)
		}
		log.Printf("Новый сертификат для домена %s добавлен в базу данных", data.Domain)
	}

	// Получаем информацию о сервере для сохранения сертификата
	var serverInfo models.Server
	err = tx.Get(&serverInfo, "SELECT id, hostname, port, username, cert_config_path, server_status FROM server WHERE id = ?", data.ServerId)
	if err != nil {
		return fmt.Errorf("не удалось получить информацию о сервере: %w", err)
	}

	// Получаем домашний каталог пользователя
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("не удалось определить домашний каталог пользователя: %w", err)
	}

	// Сохраняем сертификат на сервере в зависимости от типа приложения
	switch data.AppType {
	case "nginx":
		// Создаем пути для файлов сертификата и ключа на удаленном сервере
		certPath := fmt.Sprintf("%s/%s.pem", serverInfo.CertConfigPath, data.Domain)
		keyPath := fmt.Sprintf("%s/%s.key", serverInfo.CertConfigPath, data.Domain)

		// Используем ssh клиент для передачи сертификата и ключа
		certCmd := exec.Command("ssh",
			"-i", fmt.Sprintf("%s/.ssh/id_rsa_tlss", homeDir),
			"-p", serverInfo.Port,
			fmt.Sprintf("%s@%s", serverInfo.Username, serverInfo.Hostname),
			fmt.Sprintf("echo '%s' > %s", string(certPEM), certPath))

		keyCmd := exec.Command("ssh",
			"-i", fmt.Sprintf("%s/.ssh/id_rsa_tlss", homeDir),
			"-p", serverInfo.Port,
			fmt.Sprintf("%s@%s", serverInfo.Username, serverInfo.Hostname),
			fmt.Sprintf("echo '%s' > %s && chmod 600 %s", string(keyPEM), keyPath, keyPath))

		// Выполняем команды и проверяем результат
		if err = certCmd.Run(); err != nil {
			return fmt.Errorf("не удалось сохранить сертификат на удаленном сервере: %w", err)
		}

		if err = keyCmd.Run(); err != nil {
			return fmt.Errorf("не удалось сохранить ключ на удаленном сервере: %w", err)
		}

		log.Printf("Сертификат и ключ успешно сохранены на удаленном сервере %s:%s по путям %s и %s",
			serverInfo.Hostname, serverInfo.Port, certPath, keyPath)

	case "haproxy":
		// Для HAProxy нужно объединить промежуточный сертификат, сертификат сервера и ключ в один файл
		// Получаем промежуточный сертификат из таблицы sub_ca_tlss
		var subCACert string
		err = tx.Get(&subCACert, "SELECT public_key FROM sub_ca_tlss WHERE id = 1")
		if err != nil {
			return fmt.Errorf("не удалось получить промежуточный сертификат: %w", err)
		}

		// Объединяем промежуточный сертификат, сертификат сервера и его ключ в один файл
		// Порядок: сертификат сервера, промежуточный сертификат, ключ
		combinedContent := fmt.Sprintf("%s\n%s\n%s", string(certPEM), subCACert, string(keyPEM))

		// Путь для сохранения объединенного файла на удаленном сервере
		combinedPath := fmt.Sprintf("%s/%s.pem", serverInfo.CertConfigPath, data.Domain)

		// Используем ssh клиент для передачи объединенного файла
		combinedCmd := exec.Command("ssh",
			"-i", fmt.Sprintf("%s/.ssh/id_rsa_tlss", homeDir),
			"-p", serverInfo.Port,
			fmt.Sprintf("%s@%s", serverInfo.Username, serverInfo.Hostname),
			fmt.Sprintf("echo '%s' > %s && chmod 600 %s", combinedContent, combinedPath, combinedPath))

		// Выполняем команду и проверяем результат
		if err = combinedCmd.Run(); err != nil {
			return fmt.Errorf("не удалось сохранить объединенный файл сертификата и ключа на удаленном сервере: %w", err)
		}

		log.Printf("Объединенный файл сертификата и ключа успешно сохранен на удаленном сервере %s:%s по пути %s",
			serverInfo.Hostname, serverInfo.Port, combinedPath)

	default:
		log.Printf("Тип приложения %s не поддерживается для сохранения сертификата", data.AppType)
	}

	// Если все операции прошли успешно, фиксируем транзакцию
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("не удалось зафиксировать транзакцию: %w", err)
	}

	if certExists {
		log.Printf("Успешно обновлен RSA сертификат для домена %s", data.Domain)
	} else {
		log.Printf("Успешно сгенерирован новый RSA сертификат для домена %s", data.Domain)
	}
	return nil
}
