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
	_, err = db.Exec(`INSERT OR IGNORE INTO root_ca_tlss (id, state) VALUES (1, false)`)
	if err != nil {
		return err
	}

	// Check certificate state in database using sqlx
	var state bool
	err = db.Get(&state, "SELECT COALESCE(state, false) FROM root_ca_tlss WHERE id = 1")
	if err != nil {
		return err
	}

	// If state is true, certificate already exists
	if state {
		return nil
	}

	// Generate private key
	privateKey, err := rsa.GenerateKey(rand.Reader, viper.GetInt("root_ca_tlss.key_size"))
	if err != nil {
		return err
	}

	// Prepare certificate template
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
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
			viper.GetString("root_ca_tlss.crl_url"),
		},
	}

	// Create certificate
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

	// Save certificate to file
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

	// Save private key to file
	keyFile, err := os.Create(viper.GetString("root_ca_tlss.key"))
	if err != nil {
		return err
	}
	defer keyFile.Close()

	// Encode and write the private key in PEM format
	err = pem.Encode(keyFile, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})
	if err != nil {
		return err
	}

	// After successful certificate creation, ensure the state is updated
	result, err := db.Exec("UPDATE root_ca_tlss SET state = true, common_name = ?, country_name = ?, state_province = ?, locality_name = ?, organization = ?, organization_unit = ?, email = ?, ttl = ? WHERE id = 1",
		viper.GetString("root_ca_tlss.commonName"),
		viper.GetString("root_ca_tlss.countryName"),
		viper.GetString("root_ca_tlss.stateProvince"),
		viper.GetString("root_ca_tlss.localityName"),
		viper.GetString("root_ca_tlss.organization"),
		viper.GetString("root_ca_tlss.organizationUnit"),
		viper.GetString("root_ca_tlss.email"),
		viper.GetInt("root_ca_tlss.ttl"),
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

	return nil
}
