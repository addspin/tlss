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
	"path/filepath"
	"strings"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

// GenerateRootCA создаёт корневой CA по параметрам из data, сохраняет публичный и приватный ключи в файлы
// согласно ca_tlss.path_cert и ca_tlss.path_key, записывает публичный ключ в ca_certs (type_ca = 'Root')
func GenerateRSARootCA(data *models.CAData, db *sqlx.DB) error {
	if data == nil || db == nil {
		return fmt.Errorf("GenerateRootCA: invalid arguments")
	}

	keyBits := data.KeyLength
	if keyBits <= 0 {
		keyBits = 4096
	}

	privateKey, err := rsa.GenerateKey(rand.Reader, keyBits)
	if err != nil {
		return err
	}

	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}
	serialNumberStr := strings.ToUpper(serialNumber.Text(16))

	notBefore := time.Now()
	notAfter := notBefore.AddDate(0, 0, data.TTL)

	template := x509.Certificate{
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
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		CRLDistributionPoints: []string{viper.GetString("RootCAcrl.crlURL")},
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	// Выбираем место хранения корневого сертификата и закрытого ключа в директории на сервере
	if viper.GetBool("CApath.server") {

		// Пути сохранения из config: ca_tlss.path_cert и ca_tlss.path_key
		certPath := viper.GetString("ca_tlss.path_cert")
		keyPath := viper.GetString("ca_tlss.path_key")
		if certPath == "" || keyPath == "" {
			return fmt.Errorf("ca_tlss.path_cert/ca_tlss.path_key not set in configuration")
		}

		// Создать директории при необходимости
		if err := os.MkdirAll(filepath.Dir(certPath), 0755); err != nil {
			return err
		}
		if err := os.MkdirAll(filepath.Dir(keyPath), 0755); err != nil {
			return err
		}

		// Записать сертификат в файл
		certFile, err := os.Create(certPath)
		if err != nil {
			return err
		}
		defer certFile.Close()
		if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certBytes}); err != nil {
			return err
		}

		// Записать приватный ключ в файл
		keyFile, err := os.Create(keyPath)
		if err != nil {
			return err
		}
		defer keyFile.Close()
		if err := pem.Encode(keyFile, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)}); err != nil {
			return err
		}
	}
	// Выбираем место хранения корневого сертификата и закрытого ключа в БД
	if viper.GetBool("CApath.db") {

		// PEM для БД
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certBytes})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privateKey)})

		// Шифруем приватный ключ перед записью в БД
		aes := Aes{}
		encryptedKey, err := aes.Encrypt(keyPEM, AesSecretKey.Key)
		if err != nil {
			return fmt.Errorf("root CA: error encrypting private key: %w", err)
		}

		tx := db.MustBegin()

		// Всегда вставляем новую запись в ca_certs (type_ca = 'Root') для генерации нового ID
		daysLeft := int(time.Until(notAfter).Hours() / 24)
		_, err = tx.Exec(`
		INSERT INTO ca_certs (
			algorithm, type_ca, key_length, ttl, recreate, common_name, country_name, state_province, locality_name,
			organization, organization_unit, email, public_key, private_key, cert_create_time, cert_expire_time,
			days_left, serial_number, data_revoke, reason_revoke, cert_status
		) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
	`,
			data.Algorithm, "Root", keyBits, data.TTL, data.Recreate, data.CommonName, data.CountryName, data.StateProvince, data.LocalityName,
			data.Organization, data.OrganizationUnit, data.Email, string(certPEM), string(encryptedKey), notBefore.Format(time.RFC3339), notAfter.Format(time.RFC3339),
			daysLeft, serialNumberStr, "", "", 0,
		)
		if err != nil {
			return fmt.Errorf("root CA: error inserting new certificate: %w", err)
		}
		err = tx.Commit()
		if err != nil {
			return fmt.Errorf("root CA: error committing: %w", err)
		}
		// Когда отзывается Root CA автоматически пересоздается Sub CA
		data.CommonName = viper.GetString("sub_ca_tlss.commonName") // Значение Sub CA из config
		if err := GenerateRSASubCA(data, db); err != nil {
			return fmt.Errorf("GenerateRSARootCA: Error generating Sub CA %w", err)
		}
	}

	return nil
}
