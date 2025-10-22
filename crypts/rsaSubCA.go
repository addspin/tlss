package crypts

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

// GenerateSubCA создаёт промежуточный CA, используя корневой CA из базы данных или файлов (fallback)
// Параметры берутся из data. Записывает сертификат/приватный ключ в ca_certs (type_ca = 'Sub'),
func GenerateRSASubCA(data *models.CAData, db *sqlx.DB) error {
	if data == nil || db == nil {
		return fmt.Errorf("GenerateRSASubCA: invalid arguments")
	}

	var rootCert *x509.Certificate
	var rootKey *rsa.PrivateKey
	var err error

	// Сначала пытаемся загрузить Root CA из базы данных
	var rootCA models.CAData
	err = db.Get(&rootCA, "SELECT * FROM ca_certs WHERE type_ca = 'Root' AND cert_status = 0")
	if err == nil && rootCA.CertStatus == 0 {
		// Загружаем Root CA из базы данных
		rootCertBlock, _ := pem.Decode([]byte(rootCA.PublicKey))
		if rootCertBlock == nil {
			return fmt.Errorf("GenerateRSASubCA: failed to decode root CA certificate PEM from database")
		}
		rootCert, err = x509.ParseCertificate(rootCertBlock.Bytes)
		if err != nil {
			return fmt.Errorf("GenerateRSASubCA: failed to parse root CA certificate from database: %w", err)
		}

		// Расшифровываем приватный ключ Root CA
		aes := Aes{}
		decryptedKey, err := aes.Decrypt([]byte(rootCA.PrivateKey), AesSecretKey.Key)
		if err != nil {
			return fmt.Errorf("GenerateRSASubCA: failed to decrypt root CA private key: %w", err)
		}

		rootKeyBlock, _ := pem.Decode(decryptedKey)
		if rootKeyBlock == nil {
			return fmt.Errorf("GenerateRSASubCA: failed to decode root CA private key PEM from database")
		}
		rootKey, err = x509.ParsePKCS1PrivateKey(rootKeyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("GenerateRSASubCA: failed to parse root CA private key from database: %w", err)
		}
	} else {
		// Fallback: загружаем Root CA из файлов
		rootCertPath := viper.GetString("ca_tlss.path_cert")
		rootKeyPath := viper.GetString("ca_tlss.path_key")
		if rootCertPath == "" || rootKeyPath == "" {
			return fmt.Errorf("GenerateRSASubCA: Root CA not found in database and ca_tlss.path_cert/ca_tlss.path_key not set in configuration")
		}

		rootCertData, err := os.ReadFile(rootCertPath)
		if err != nil {
			return fmt.Errorf("GenerateRSASubCA: failed to read root CA certificate from file: %w", err)
		}
		rootKeyData, err := os.ReadFile(rootKeyPath)
		if err != nil {
			return fmt.Errorf("GenerateRSASubCA: failed to read root CA private key from file: %w", err)
		}
		rootCertBlock, _ := pem.Decode(rootCertData)
		if rootCertBlock == nil {
			return fmt.Errorf("GenerateRSASubCA: failed to decode root CA certificate PEM from file")
		}
		rootCert, err = x509.ParseCertificate(rootCertBlock.Bytes)
		if err != nil {
			return fmt.Errorf("GenerateRSASubCA: failed to parse root CA certificate from file: %w", err)
		}
		rootKeyBlock, _ := pem.Decode(rootKeyData)
		if rootKeyBlock == nil {
			return fmt.Errorf("GenerateRSASubCA: failed to decode root CA private key PEM from file")
		}
		rootKey, err = x509.ParsePKCS1PrivateKey(rootKeyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("GenerateRSASubCA: failed to parse root CA private key from file: %w", err)
		}
	}

	keyBits := data.KeyLength
	if keyBits <= 0 {
		keyBits = 4096
	}
	subCAKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	serialNumberStr := strings.ToUpper(serialNumber.Text(16))

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, data.TTL)

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
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		CRLDistributionPoints: []string{viper.GetString("SubCAcrl.crlURL")},
	}

	subCACertDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &subCAKey.PublicKey, rootKey)
	if err != nil {
		return err
	}

	subCACertPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: subCACertDER})
	subCAKeyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(subCAKey)})

	// Шифруем приватный ключ перед записью в БД
	aes := Aes{}
	encryptedKey, err := aes.Encrypt(subCAKeyPEM, AesSecretKey.Key)
	if err != nil {
		return err
	}
	// currentTime := time.Now().Format(time.RFC3339)
	// certStatus := 0   // 0 - valid
	// revokeStatus := 2 // 2 - revoked
	tx := db.MustBegin()
	// Перед вставкой нового сертификата помечаем текущий активный Sub CA как superseded
	// _, err = tx.Exec(`UPDATE ca_certs SET
	// cert_status = ?,
	// data_revoke = ?,
	// reason_revoke = ?
	// WHERE type_ca = 'Sub' AND cert_status = ?`, revokeStatus, currentTime, "superseded", certStatus)
	// if err != nil {
	// 	return fmt.Errorf("sub CA: ошибка при обновлении метки об отзыве сертификата: %w", err)
	// }

	// Всегда вставляем новую запись в ca_certs (type_ca = 'Sub') для генерации нового ID
	daysLeft := int(time.Until(notAfter).Hours() / 24)
	_, err = tx.Exec(`
		INSERT INTO ca_certs (
			algorithm, type_ca, key_length, ttl, recreate, common_name, country_name, state_province, locality_name,
			organization, organization_unit, email, public_key, private_key, cert_create_time, cert_expire_time,
			days_left, serial_number, data_revoke, reason_revoke, cert_status
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
	`,
		data.Algorithm, "Sub", keyBits, data.TTL, data.Recreate, data.CommonName, data.CountryName, data.StateProvince, data.LocalityName,
		data.Organization, data.OrganizationUnit, data.Email, string(subCACertPEM), string(encryptedKey), notBefore.Format(time.RFC3339), notAfter.Format(time.RFC3339),
		daysLeft, serialNumberStr, "", "", 0,
	)
	if err != nil {
		return fmt.Errorf("sub CA: error inserting new certificate: %w", err)
	}
	err = tx.Commit()
	if err != nil {
		return fmt.Errorf("sub CA: error committing: %w", err)
	}
	return nil
}
