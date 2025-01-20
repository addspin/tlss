package crypts

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

func CreateAndSignED25519Cert(caCert *x509.Certificate, caPrivKey interface{}) (*x509.Certificate, ed25519.PrivateKey, error) {
	// Генерируем пару ключей ED25519
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	// Создаем шаблон сертификата
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "ED25519 Certificate",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	// Подписываем сертификат с помощью CA (RSA)
	certBytes, err := x509.CreateCertificate(rand.Reader, template, caCert, pub, caPrivKey)
	if err != nil {
		return nil, nil, err
	}

	// Парсим созданный сертификат
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		return nil, nil, err
	}

	return cert, priv, nil
}
