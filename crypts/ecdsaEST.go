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
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

// Генерирует ECDSA ключевую пару для EST сертификатов
func GenerateESTECDSAKeyPair(keyLength int) (*ecdsa.PrivateKey, error) {
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
		curve = elliptic.P256()
	}

	privateKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}
	return privateKey, nil
}

// Кодирует приватный ключ ECDSA в формат PEM
func EncodeESTECDSAPrivateKeyToPEM(privateKey *ecdsa.PrivateKey) ([]byte, error) {
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

// Генерирует ECDSA сертификат для EST, подписанный выбранным CA,
// и сохраняет его в таблицу est_certs
func GenerateESTECDSACertificate(data *models.ESTCert, db *sqlx.DB) (certPem, keyPem []byte, err error) {
	// Ключевая пара
	privateKey, err := GenerateESTECDSAKeyPair(data.KeyLength)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}

	// Серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	data.SerialNumber = ESTStandardizeSerialNumber(serialNumber)
	slog.Info("Сгенерирован серийный номер для EST ECDSA сертификата",
		slog.String("common_name", data.CommonName),
		slog.String("serial_number", data.SerialNumber))

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

	// Подписывающий CA
	var subCACert *x509.Certificate
	var subCAKey any
	if data.SigningCAId > 0 {
		subCACert, subCAKey, err = ExtractExtCA(db, data.SigningCAId)
		if err != nil {
			return nil, nil, fmt.Errorf("GenerateESTECDSACertificate: failed to extract external CA: %w", err)
		}
	} else {
		if ExtractCA.SubCAcert == nil || ExtractCA.SubCAKey == nil {
			err = ExtractCA.ExtractSubCA(db)
			if err != nil {
				return nil, nil, fmt.Errorf("GenerateESTECDSACertificate: failed to extract intermediate CA: %w", err)
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

	// PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal EC private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
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

	daysLeft := int(expiry.Sub(now).Hours() / 24)

	// Сохраняем в БД
	tx := db.MustBegin()
	var txCommitted bool
	defer func() {
		if !txCommitted && tx != nil {
			tx.Rollback()
			slog.Error("Транзакция отменена для EST ECDSA сертификата",
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

	slog.Info("Успешно создан EST ECDSA сертификат", slog.String("common_name", data.CommonName))
	return certPEM, keyPEM, nil
}

// Пересоздаёт ECDSA EST сертификат с новым ключом и подписью текущего активного Sub CA.
func RecreateESTECDSACertificate(data *models.ESTCert, db *sqlx.DB) error {
	// Ключевая пара
	privateKey, err := GenerateESTECDSAKeyPair(data.KeyLength)
	if err != nil {
		return fmt.Errorf("failed to generate ECDSA key pair: %w", err)
	}

	// Серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}
	data.SerialNumber = ESTStandardizeSerialNumber(serialNumber)
	slog.Info("Сгенерирован серийный номер для EST ECDSA сертификата при пересоздании",
		slog.String("common_name", data.CommonName),
		slog.String("serial_number", data.SerialNumber))

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

	// Подписывающий CA
	var subCACert *x509.Certificate
	var subCAKey any
	if data.SigningCAId > 0 {
		subCACert, subCAKey, err = ExtractExtCA(db, data.SigningCAId)
		if err != nil {
			return fmt.Errorf("RecreateESTECDSACertificate: failed to extract external CA: %w", err)
		}
	} else {
		if ExtractCA.SubCAcert == nil || ExtractCA.SubCAKey == nil {
			err = ExtractCA.ExtractSubCA(db)
			if err != nil {
				return fmt.Errorf("RecreateESTECDSACertificate: failed to extract intermediate CA: %w", err)
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

	// PEM
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return fmt.Errorf("failed to marshal EC private key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "EC PRIVATE KEY",
		Bytes: keyDER,
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

	daysLeft := int(expiry.Sub(now).Hours() / 24)

	// Обновляем запись в БД
	tx := db.MustBegin()
	var txCommitted bool
	defer func() {
		if !txCommitted && tx != nil {
			tx.Rollback()
			slog.Error("Транзакция отменена для пересоздания EST ECDSA сертификата",
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

	slog.Info("Успешно пересоздан EST ECDSA сертификат",
		slog.String("common_name", data.CommonName),
		slog.Int("id", data.Id))
	return nil
}
