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
	"path/filepath"
	"strings"
	"time"

	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func GenerateRootCA() error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// First, try to insert if not exists
	_, err = db.Exec(`INSERT OR IGNORE INTO root_ca_tlss (id, root_ca_status, create_time) VALUES (1, 1, ?)`, time.Now().Format(time.RFC3339))
	if err != nil {
		return err
	}

	// Check certificate root_ca_status in database using sqlx
	var root_ca_status int
	err = db.Get(&root_ca_status, "SELECT COALESCE(root_ca_status, 0) FROM root_ca_tlss WHERE id = 1")
	if err != nil {
		return err
	}

	// If status is 0, certificate is valid and we don't need to create a new one
	if root_ca_status == 0 {
		return nil
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, viper.GetInt("root_ca_tlss.key_size"))
	if err != nil {
		return err
	}

	// Генерируем случайный серийный номер замена функции из rsa
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать серийный номер: %w", err)
	}
	hexStr := serialNumber.Text(16)
	serialNumberStr := strings.ToUpper(hexStr)

	// Prepare certificate template
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         viper.GetString("root_ca_tlss.commonName"),
			Country:            []string{viper.GetString("root_ca_tlss.countryName")},
			Province:           []string{viper.GetString("root_ca_tlss.stateProvince")},
			Locality:           []string{viper.GetString("root_ca_tlss.localityName")},
			Organization:       []string{viper.GetString("root_ca_tlss.organization")},
			OrganizationalUnit: []string{viper.GetString("root_ca_tlss.organizationUnit")},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{1, 2, 840, 113549, 1, 9, 1},
					Value: viper.GetString("root_ca_tlss.email"),
				},
			},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(0, 0, viper.GetInt("root_ca_tlss.ttl")),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		CRLDistributionPoints: []string{
			viper.GetString("crl.crlURL"),
		},
	}

	// Создание корневого CA сертификата
	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}

	certPath := viper.GetString("root_ca_tlss.path")
	// Create directory if it doesn't exist
	dir := filepath.Dir(certPath)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Сохранение корневого CA сертификата в файл
	certFile, err := os.Create(certPath)
	if err != nil {
		return err
	}
	defer certFile.Close()

	err = pem.Encode(certFile, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return err
	}
	// Сохранение корневого CA сертификата в PEM формате в память для передачи в базу данных
	rootCACertPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})

	// Сохранение приватного ключа в файл
	keyFile, err := os.Create(viper.GetString("root_ca_tlss.key"))
	if err != nil {
		return err
	}
	defer keyFile.Close()

	// Кодирование и запись приватного ключа в PEM формате
	err = pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return err
	}

	// После успешного создания сертификата, обновляем состояние в базе данных
	result, err := db.Exec(`
	UPDATE root_ca_tlss
	SET 
		root_ca_status = 0,
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
		serial_number = ?,
		data_revoke = ?,
		reason_revoke = ?
		WHERE id = 1`,
		time.Now().Format(time.RFC3339),
		viper.GetString("root_ca_tlss.commonName"),
		viper.GetString("root_ca_tlss.countryName"),
		viper.GetString("root_ca_tlss.stateProvince"),
		viper.GetString("root_ca_tlss.localityName"),
		viper.GetString("root_ca_tlss.organization"),
		viper.GetString("root_ca_tlss.organizationUnit"),
		viper.GetString("root_ca_tlss.email"),
		viper.GetInt("root_ca_tlss.ttl"),
		string(rootCACertPEM),
		serialNumberStr,
		"",
		"",
	)
	if err != nil {
		return err
	}

	// Verify that the update was successful
	rowsAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowsAffected == 0 {
		return fmt.Errorf("failed to update state in database")
	}
	// Generate sub CA
	err = GenerateSubCA()
	if err != nil {
		return err
	}
	return nil
}
