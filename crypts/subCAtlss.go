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
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func GenerateSubCA() error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// First, try to insert if not exists
	_, err = db.Exec(`INSERT OR IGNORE INTO sub_ca_tlss (id, sub_ca_status, create_time) VALUES (1, 1, ?)`, time.Now().Format(time.RFC3339))
	if err != nil {
		return err
	}

	// Check if root CA certificate is newer than sub CA certificate
	var rootCACreationTime, subCACreationTime string

	// Get root CA creation time from database
	err = db.QueryRow("SELECT COALESCE(create_time, ?) FROM root_ca_tlss WHERE id = 1", time.Now().Format(time.RFC3339)).Scan(&rootCACreationTime)
	if err != nil {
		return err
	}

	// Get sub CA creation time from database
	err = db.QueryRow("SELECT COALESCE(create_time, ?) FROM sub_ca_tlss WHERE id = 1", time.Now().Format(time.RFC3339)).Scan(&subCACreationTime)
	if err != nil {
		return err
	}

	// Парсим времена создания
	// Используем только формат RFC3339
	rootTime, err := time.Parse(time.RFC3339, rootCACreationTime)
	if err != nil {
		return err
	}

	// Используем только формат RFC3339
	subTime, err := time.Parse(time.RFC3339, subCACreationTime)
	if err != nil {
		return err
	}

	// If root CA is newer than sub CA, force recreation by setting sub_ca_status to 1
	if rootTime.After(subTime) {
		_, err = db.Exec("UPDATE sub_ca_tlss SET sub_ca_status = 1 WHERE id = 1")
		if err != nil {
			return err
		}
	}

	// Check certificate sub_ca_status in database using sqlx
	var sub_ca_status int
	err = db.Get(&sub_ca_status, "SELECT COALESCE(sub_ca_status, 0) FROM sub_ca_tlss WHERE id = 1")
	if err != nil {
		return err
	}

	// If status is 0, certificate is valid and we don't need to create a new one
	if sub_ca_status == 0 {
		return nil
	}

	// Otherwise, we need to create a new certificate
	// Load root CA certificate and private key
	rootCertPath := viper.GetString("root_ca_tlss.path")
	rootKeyPath := viper.GetString("root_ca_tlss.key")

	// Read certificate file
	rootCertData, err := os.ReadFile(rootCertPath)
	if err != nil {
		return fmt.Errorf("failed to read root CA certificate: %w", err)
	}

	// Read private key file
	rootKeyData, err := os.ReadFile(rootKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read root CA private key: %w", err)
	}

	// Decode root CA certificate
	rootCertBlock, _ := pem.Decode(rootCertData)
	if rootCertBlock == nil {
		return fmt.Errorf("failed to decode root CA certificate PEM")
	}
	rootCert, err := x509.ParseCertificate(rootCertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root CA certificate: %w", err)
	}

	// Decode root CA private key
	rootKeyBlock, _ := pem.Decode(rootKeyData)
	if rootKeyBlock == nil {
		return fmt.Errorf("failed to decode root CA private key PEM")
	}
	rootKey, err := x509.ParsePKCS1PrivateKey(rootKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse root CA private key: %w", err)
	}

	// Generate new key pair for sub CA
	subCAKey, err := rsa.GenerateKey(rand.Reader, viper.GetInt("sub_ca_tlss.key_size"))
	if err != nil {
		return err
	}

	// Generate random serial number замена функции из rsa
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return err
	}
	hexStr := serialNumber.Text(16)
	serialNumberStr := strings.ToUpper(hexStr)

	// Prepare certificate template
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         viper.GetString("sub_ca_tlss.commonName"),
			Country:            []string{viper.GetString("sub_ca_tlss.countryName")},
			Province:           []string{viper.GetString("sub_ca_tlss.stateProvince")},
			Locality:           []string{viper.GetString("sub_ca_tlss.localityName")},
			Organization:       []string{viper.GetString("sub_ca_tlss.organization")},
			OrganizationalUnit: []string{viper.GetString("sub_ca_tlss.organizationUnit")},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{1, 2, 840, 113549, 1, 9, 1},
					Value: viper.GetString("sub_ca_tlss.email"),
				},
			},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, viper.GetInt("sub_ca_tlss.ttl")),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		CRLDistributionPoints: []string{
			viper.GetString("crl.crlURL"),
		},
	}

	// Create sub CA certificate
	subCACertDER, err := x509.CreateCertificate(rand.Reader, template, rootCert, &subCAKey.PublicKey, rootKey)
	if err != nil {
		return err
	}

	// Encode certificate and private key to PEM
	subCACertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: subCACertDER,
	})
	subCAKeyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(subCAKey),
	})

	// Encrypt private key before storing
	aes := Aes{}
	encryptedKey, err := aes.Encrypt(subCAKeyPEM, AesSecretKey.Key)
	if err != nil {
		return err
	}

	// Update the final database insert to use UPDATE instead of INSERT
	_, err = db.Exec(`
		UPDATE sub_ca_tlss
		SET 
			sub_ca_status = 0,
			create_time = ?,
			common_name = ?,
			country_name = ?,
			state_province = ?,
			locality_name = ?,
			organization = ?,
			organization_unit = ?,
			email = ?,
			ttl = ?,
			public_key = ?,
			private_key = ?,
			serial_number = ?,
			data_revoke = ?,
			reason_revoke = ?
		WHERE id = 1
	`,
		time.Now().Format(time.RFC3339),
		viper.GetString("sub_ca_tlss.commonName"),
		viper.GetString("sub_ca_tlss.countryName"),
		viper.GetString("sub_ca_tlss.stateProvince"),
		viper.GetString("sub_ca_tlss.localityName"),
		viper.GetString("sub_ca_tlss.organization"),
		viper.GetString("sub_ca_tlss.organizationUnit"),
		viper.GetString("sub_ca_tlss.email"),
		viper.GetInt("sub_ca_tlss.ttl"),
		string(subCACertPEM),
		string(encryptedKey),
		serialNumberStr,
		"",
		"",
	)
	if err != nil {
		return fmt.Errorf("failed to update sub CA in database: %w", err)
	}

	// Проверяем успешность обновления
	log.Printf("Промежуточный CA сертификат успешно создан и сохранен в базе данных")
	return nil
}

// Функция standardizeSerialNumber определена в rsa.go
