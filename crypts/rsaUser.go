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
	"github.com/spf13/viper"
)

// Генерирует RSA ключевую пару
func GenerateUserRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("не удалось сгенерировать RSA ключевую пару: %w", err)
	}
	return privateKey, nil
}

// Кодирует приватный ключ RSA в формат PEM
func EncodeUserRSAPrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
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
func EncodeUserRSAPublicKeyToPEM(publicKey *rsa.PublicKey) []byte {
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
func UserStandardizeSerialNumber(serialNumber *big.Int) string {
	hexStr := serialNumber.Text(16)
	return strings.ToUpper(hexStr)
}

// Генерирует RSA сертификат, подписанный промежуточным CA,
// и сохраняет его в базу данных
func GenerateUserRSACertificate(data *models.UserCerts, db *sqlx.DB) error {

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

	// Стандартизируем серийный номер и сохраняем
	data.SerialNumber = UserStandardizeSerialNumber(serialNumber)
	log.Printf("Сгенерирован серийный номер для сертификата %s: %s", data.CommonName, data.SerialNumber)

	// Подготавливаем шаблон сертификата
	//dnsNames = SAN
	// dnsNames := []string{data.CommonName}
	// if data.Wildcard {
	// 	dnsNames = append(dnsNames, "*."+data.Domain)
	// }

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
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		CRLDistributionPoints: []string{
			viper.GetString("crlUser.crlURL"),
		},
		OCSPServer: []string{
			viper.GetString("ocspUser.ocspURL"),
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
		log.Printf("ВНИМАНИЕ: Приватный ключ сохраняется без шифрования для домена %s, т.к. AesSecretKey.Key не установлен", data.CommonName)
		encryptedKey = keyPEM
	}

	// Шифруем password
	encryptedPassword, err := aes.Encrypt([]byte(data.Password), AesSecretKey.Key)
	if err != nil {
		return fmt.Errorf("не удалось зашифровать password: %w", err)
	}
	data.Password = string(encryptedPassword)

	// Вычисляем количество дней до истечения сертификата
	daysLeft := int(expiry.Sub(now).Hours() / 24)
	data.DaysLeft = daysLeft

	// Сохраняем сертификат в БД
	tx := db.MustBegin()
	var txCommitted bool
	defer func() {
		// Если произошла паника или транзакция не была зафиксирована, выполняем откат
		if !txCommitted && tx != nil {
			tx.Rollback()
			log.Printf("Транзакция отменена из-за ошибки для домена %s", data.CommonName)
		}
	}()

	// Пробуем найти существующую запись для сущности
	var exists bool
	err = tx.Get(&exists, `SELECT EXISTS(SELECT 1 FROM user_certs WHERE common_name = ? AND entity_id = ?)`, data.CommonName, data.EntityId)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("ошибка проверки существования common_name: %v", err)
	}

	if exists {
		// Если запись существует, обновляем её
		_, err = tx.Exec(`UPDATE user_certs SET 
                algorithm = ?, key_length = ?, ttl = ?, recreate = ?,
                common_name = ?, country_name = ?, state_province = ?, locality_name = ?,
                organization = ?, organization_unit = ?, email = ?, password = ?,
                public_key = ?, private_key = ?, cert_create_time = ?, cert_expire_time = ?,
                serial_number = ?, data_revoke = ?, reason_revoke = ?, cert_status = ?, days_left = ?
            WHERE common_name = ? AND entity_id = ?`,
			data.Algorithm, data.KeyLength, data.TTL, data.Recreate,
			data.CommonName, data.CountryName, data.StateProvince, data.LocalityName,
			data.Organization, data.OrganizationUnit, data.Email, data.Password,
			string(certPEM), string(encryptedKey), now.Format(time.RFC3339), expiry.Format(time.RFC3339),
			data.SerialNumber, "", "", 0, data.DaysLeft,
			data.CommonName, data.EntityId)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("не удалось обновить существующий сертификат в базе данных: %w", err)
		}
		log.Printf("Сертификат для common_name %s обновлен в базе данных (ID: %d)", data.CommonName, data.Id)
	} else {
		// Сертификат не существует, добавляем новый
		_, err = tx.Exec(`INSERT INTO user_certs (
                entity_id, algorithm, key_length, ttl, recreate,
                common_name, country_name, state_province, locality_name,
                organization, organization_unit, email, password,
                public_key, private_key, cert_create_time, cert_expire_time,
                serial_number, data_revoke, reason_revoke, cert_status, days_left
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			data.EntityId, data.Algorithm, data.KeyLength, data.TTL, data.Recreate,
			data.CommonName, data.CountryName, data.StateProvince, data.LocalityName,
			data.Organization, data.OrganizationUnit, data.Email, data.Password,
			string(certPEM), string(encryptedKey), now.Format(time.RFC3339), expiry.Format(time.RFC3339),
			data.SerialNumber, "", "", 0, data.DaysLeft)
		if err != nil {
			tx.Rollback()
			return fmt.Errorf("не удалось добавить новый сертификат в базу данных: %w", err)
		}
		log.Printf("Новый сертификат для common_name %s добавлен в базу данных", data.CommonName)
	}

	// Если все операции прошли успешно, фиксируем транзакцию
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("не удалось зафиксировать транзакцию: %w", err)
	}
	txCommitted = true

	if exists {
		log.Printf("Успешно обновлен RSA сертификат для common_name %s", data.CommonName)
	} else {
		log.Printf("Успешно сгенерирован новый RSA сертификат для common_name %s", data.CommonName)
	}
	return nil
}
