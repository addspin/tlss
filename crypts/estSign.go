package crypts

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"math/big"
	"time"

	"github.com/jmoiron/sqlx"
)

// SignCSR верифицирует PKCS#10 CSR и подписывает его указанным CA.
// signingCAId=0 — внутренний SubCA; >0 — внешний CA из ca_certs_ext.
// Возвращает DER-encoded сертификат.
func SignCSR(csrDER []byte, db *sqlx.DB, signingCAId int, ttlDays int) ([]byte, error) {
	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid CSR signature: %w", err)
	}

	var issuerCert *x509.Certificate
	var issuerKey crypto.PrivateKey

	if signingCAId > 0 {
		issuerCert, issuerKey, err = ExtractExtCA(db, signingCAId)
		if err != nil {
			return nil, fmt.Errorf("failed to extract external CA: %w", err)
		}
	} else {
		if ExtractCA.SubCAcert == nil || ExtractCA.SubCAKey == nil {
			if err := ExtractCA.ExtractSubCA(db); err != nil {
				return nil, fmt.Errorf("failed to extract internal SubCA: %w", err)
			}
		}
		issuerCert = ExtractCA.SubCAcert
		issuerKey = ExtractCA.SubCAKey
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial: %w", err)
	}

	now := time.Now()
	expiry := now.AddDate(0, 0, ttlDays)
	template := &x509.Certificate{
		SerialNumber:   serial,
		Subject:        csr.Subject,
		NotBefore:      now,
		NotAfter:       expiry,
		KeyUsage:       x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		DNSNames:       csr.DNSNames,
		IPAddresses:    csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
		URIs:           csr.URIs,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, issuerCert, csr.PublicKey, issuerKey)
	if err != nil {
		return nil, fmt.Errorf("failed to sign certificate: %w", err)
	}
	return certDER, nil
}
