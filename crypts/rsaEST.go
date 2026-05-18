package crypts

import (
	"crypto/rand"
	"crypto/rsa"
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
	"github.com/spf13/viper"
)

// Генерирует RSA ключевую пару для EST сертификата
func GenerateESTRSAKeyPair(bits int) (*rsa.PrivateKey, error) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}
	return privateKey, nil
}

// Кодирует приватный ключ RSA в формат PEM
func EncodeESTRSAPrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	privateKeyBytes := x509.MarshalPKCS1PrivateKey(privateKey)
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	return privateKeyPEM
}

// ESTStandardizeSerialNumber возвращает серийный номер в стандартизированном формате
// верхний регистр без ведущих нулей
func ESTStandardizeSerialNumber(serialNumber *big.Int) string {
	hexStr := serialNumber.Text(16)
	return strings.ToUpper(hexStr)
}

// Генерирует RSA сертификат для EST, подписанный выбранным CA,
// и сохраняет его в таблицу est_certs
func GenerateESTRSACertificate(data *models.ESTCert, db *sqlx.DB) (certPem, keyPem []byte, err error) {
	// Генерируем новую RSA ключевую пару
	privateKey, err := rsa.GenerateKey(rand.Reader, data.KeyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	data.SerialNumber = ESTStandardizeSerialNumber(serialNumber)
	slog.Info("Сгенерирован серийный номер для EST сертификата",
		slog.String("common_name", data.CommonName),
		slog.String("serial_number", data.SerialNumber))

	// SAN
	san := ParseSAN(data.CommonName, data.SAN, "", false)

	now := time.Now()
	expiry := now.AddDate(0, 0, data.TTL)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: data.CommonName,
		},
		NotBefore:             now,
		NotAfter:              expiry,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              san.DNSNames,
		IPAddresses:           san.IPAddresses,
		EmailAddresses:        san.EmailAddresses,
		CRLDistributionPoints: []string{
			viper.GetString("CAcrl.subCACrlURL"),
		},
	}

	// Получаем подписывающий CA сертификат и ключ
	var subCACert *x509.Certificate
	var subCAKey any
	if data.SigningCAId > 0 {
		subCACert, subCAKey, err = ExtractExtCA(db, data.SigningCAId)
		if err != nil {
			return nil, nil, fmt.Errorf("GenerateESTRSACertificate: failed to extract external CA: %w", err)
		}
	} else {
		if ExtractCA.SubCAcert == nil || ExtractCA.SubCAKey == nil {
			err = ExtractCA.ExtractSubCA(db)
			if err != nil {
				return nil, nil, fmt.Errorf("GenerateESTRSACertificate: failed to extract intermediate CA certificate and key: %w", err)
			}
		}
		subCACert = ExtractCA.SubCAcert
		subCAKey = ExtractCA.SubCAKey
	}
	aes := Aes{}

	// Создаём сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, template, subCACert, &privateKey.PublicKey, subCAKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
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

	// Шифруем приватный ключ
	var encryptedKey []byte
	if len(AesSecretKey.Key) > 0 {
		encryptedKey, err = aes.Encrypt(keyPEM, AesSecretKey.Key)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to encrypt private key: %w", err)
		}
	} else {
		slog.Warn("Приватный ключ EST сохраняется без шифрования",
			slog.String("common_name", data.CommonName))
		encryptedKey = keyPEM
	}

	// Шифруем password
	encryptedPassword, err := aes.Encrypt([]byte(data.Password), AesSecretKey.Key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encrypt password: %w", err)
	}
	data.Password = string(encryptedPassword)

	// Дней до истечения
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	// Сохраняем в БД
	tx := db.MustBegin()
	var txCommitted bool
	defer func() {
		if !txCommitted && tx != nil {
			tx.Rollback()
			slog.Error("Транзакция отменена для EST сертификата",
				slog.String("common_name", data.CommonName),
				slog.Int("est_user_id", data.ESTUserId))
		}
	}()

	_, err = tx.Exec(`INSERT INTO est_certs (
		est_user_id, serial_number, signing_ca_id, common_name, san,
		public_key, private_key, password,
		algorithm, key_length, ttl,
		cert_create_time, cert_expire_time, days_left,
		data_revoke, reason_revoke, cert_status
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		data.ESTUserId, data.SerialNumber, data.SigningCAId, data.CommonName, data.SAN,
		string(certPEM), string(encryptedKey), data.Password,
		data.Algorithm, data.KeyLength, data.TTL,
		now.Format(time.RFC3339), expiry.Format(time.RFC3339), daysLeft,
		"", "", 0)
	if err != nil {
		tx.Rollback()
		return nil, nil, fmt.Errorf("failed to insert EST cert: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return nil, nil, fmt.Errorf("failed to commit transaction: %w", err)
	}
	txCommitted = true

	slog.Info("Успешно создан EST RSA сертификат", slog.String("common_name", data.CommonName))
	return certPEM, keyPEM, nil
}

// Пересоздаёт RSA EST сертификат с новым ключом и подписью текущего активного Sub CA.
func RecreateESTRSACertificate(data *models.ESTCert, db *sqlx.DB) error {
	// Генерируем новую RSA ключевую пару
	privateKey, err := rsa.GenerateKey(rand.Reader, data.KeyLength)
	if err != nil {
		return fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	data.SerialNumber = ESTStandardizeSerialNumber(serialNumber)
	slog.Info("Сгенерирован серийный номер для EST RSA сертификата при пересоздании",
		slog.String("common_name", data.CommonName),
		slog.String("serial_number", data.SerialNumber))

	// SAN
	san := ParseSAN(data.CommonName, data.SAN, "", false)

	now := time.Now()
	expiry := now.AddDate(0, 0, data.TTL)

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: data.CommonName,
		},
		NotBefore:             now,
		NotAfter:              expiry,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              san.DNSNames,
		IPAddresses:           san.IPAddresses,
		EmailAddresses:        san.EmailAddresses,
		CRLDistributionPoints: []string{
			viper.GetString("CAcrl.subCACrlURL"),
		},
	}

	// Получаем подписывающий CA сертификат и ключ
	var subCACert *x509.Certificate
	var subCAKey any
	if data.SigningCAId > 0 {
		subCACert, subCAKey, err = ExtractExtCA(db, data.SigningCAId)
		if err != nil {
			return fmt.Errorf("RecreateESTRSACertificate: failed to extract external CA: %w", err)
		}
	} else {
		if ExtractCA.SubCAcert == nil || ExtractCA.SubCAKey == nil {
			err = ExtractCA.ExtractSubCA(db)
			if err != nil {
				return fmt.Errorf("RecreateESTRSACertificate: failed to extract intermediate CA certificate and key: %w", err)
			}
		}
		subCACert = ExtractCA.SubCAcert
		subCAKey = ExtractCA.SubCAKey
	}
	aes := Aes{}

	// Создаём сертификат
	certDER, err := x509.CreateCertificate(rand.Reader, template, subCACert, &privateKey.PublicKey, subCAKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
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

	// Шифруем приватный ключ
	var encryptedKey []byte
	if len(AesSecretKey.Key) > 0 {
		encryptedKey, err = aes.Encrypt(keyPEM, AesSecretKey.Key)
		if err != nil {
			return fmt.Errorf("failed to encrypt private key: %w", err)
		}
	} else {
		slog.Warn("Приватный ключ EST сохраняется без шифрования при пересоздании",
			slog.String("common_name", data.CommonName))
		encryptedKey = keyPEM
	}

	// Дней до истечения
	daysLeft := int(expiry.Sub(now).Hours() / 24)

	// Обновляем запись в БД
	tx := db.MustBegin()
	var txCommitted bool
	defer func() {
		if !txCommitted && tx != nil {
			tx.Rollback()
			slog.Error("Транзакция отменена для пересоздания EST сертификата",
				slog.String("common_name", data.CommonName),
				slog.Int("id", data.Id))
		}
	}()

	_, err = tx.Exec(`UPDATE est_certs SET
			algorithm = ?, key_length = ?, ttl = ?,
			common_name = ?, san = ?,
			public_key = ?, private_key = ?,
			cert_create_time = ?, cert_expire_time = ?,
			serial_number = ?, data_revoke = ?, reason_revoke = ?, cert_status = ?, days_left = ?
		WHERE id = ?`,
		data.Algorithm, data.KeyLength, data.TTL,
		data.CommonName, data.SAN,
		string(certPEM), string(encryptedKey),
		now.Format(time.RFC3339), expiry.Format(time.RFC3339),
		data.SerialNumber, "", "", 0, daysLeft,
		data.Id)
	if err != nil {
		tx.Rollback()
		return fmt.Errorf("failed to update EST certificate in database: %w", err)
	}

	if err = tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	txCommitted = true

	slog.Info("Успешно пересоздан EST RSA сертификат",
		slog.String("common_name", data.CommonName),
		slog.Int("id", data.Id))
	return nil
}
