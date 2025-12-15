package controllers

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/addspin/tlss/middleware"
	"github.com/gofiber/fiber/v3"
)

// CertInfo содержит информацию о сертификате
type CertInfo struct {
	Type                   string   // Тип алгоритма (RSA, ECDSA, ED25519)
	KeyLength              string   // Длина ключа в битах
	TimeToLive             string   // Оставшееся время жизни
	TimeCreate             string   // Дата создания
	Expires                string   // Дата истечения
	ExpiresIn              string   // Истекает через (в днях)
	DomainType             string   // Тип домена (Single, Wildcard, Multiple)
	Function               string   // Функция (для каких целей используется)
	CommonName             string   // Common Name
	Organization           string   // Organization
	OrgUnit                string   // Organizational Unit
	Locality               string   // Locality
	State                  string   // State/Province
	Country                string   // Country
	Email                  string   // Email
	SANs                   []string // Subject Alternative Names
	Issuer                 string   // Издатель
	SerialNumber           string   // Серийный номер
	SignatureAlgo          string   // Алгоритм подписи
	Version                int      // Версия сертификата
	IsCA                   bool     // Является ли CA
	KeyUsage               []string // Использование ключа
	ExtKeyUsage            []string // Расширенное использование ключа
	CRLDistributionPoints  []string // CRL Distribution Points
	OCSPDistributionPoints []string // OCSP Distribution Points
}

func CertInfoController(c fiber.Ctx) error {
	if c.Method() == "GET" {
		data := fiber.Map{
			"Title": "Certificate Info",
		}

		// Проверяем, является ли запрос HTMX запросом
		if c.Get("HX-Request") != "" {
			slog.Debug("Certificate Info: HTMX request received")
			err := c.Render("certInfo-content", data, "")
			if err != nil {
				slog.Error("Error rendering certInfo-content", "error", err)
				return err
			}
			return nil
		}

		// Проверяем авторизацию и выбираем нужный шаблон
		isAuthenticated := middleware.IsAuthenticated(c)

		if isAuthenticated {
			slog.Debug("Certificate Info: authenticated user request")
			// Авторизованный пользователь - показываем полное меню
			return c.Render("cert_info/certInfo", data)
		} else {
			slog.Debug("Certificate Info: public user request")
			// Неавторизованный пользователь - показываем публичное меню
			return c.Render("cert_info/certInfo-public", data)
		}
	}

	if c.Method() == "POST" {
		// Получаем загруженный файл
		file, err := c.FormFile("certificate")
		if err != nil {
			slog.Error("Error getting file", "error", err)
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to upload file",
			})
		}

		// Открываем файл
		fileContent, err := file.Open()
		if err != nil {
			slog.Error("Error opening file", "filename", file.Filename, "error", err)
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to open file",
			})
		}
		defer fileContent.Close()

		// Читаем содержимое файла
		certBytes, err := io.ReadAll(fileContent)
		if err != nil {
			slog.Error("Error reading file", "filename", file.Filename, "error", err)
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to read file",
			})
		}

		// Парсим сертификат
		certInfo, err := parseCertificate(certBytes)
		if err != nil {
			slog.Error("Error parsing certificate", "filename", file.Filename, "error", err)
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to parse certificate: " + err.Error(),
			})
		}

		return c.Render("cert_info/certDetails", fiber.Map{
			"Type":                   certInfo.Type,
			"KeyLength":              certInfo.KeyLength,
			"TimeToLive":             certInfo.TimeToLive,
			"TimeCreate":             certInfo.TimeCreate,
			"Expires":                certInfo.Expires,
			"ExpiresIn":              certInfo.ExpiresIn,
			"DomainType":             certInfo.DomainType,
			"Function":               certInfo.Function,
			"CommonName":             certInfo.CommonName,
			"Organization":           certInfo.Organization,
			"OrgUnit":                certInfo.OrgUnit,
			"Locality":               certInfo.Locality,
			"State":                  certInfo.State,
			"Country":                certInfo.Country,
			"Email":                  certInfo.Email,
			"SANs":                   certInfo.SANs,
			"Issuer":                 certInfo.Issuer,
			"SerialNumber":           certInfo.SerialNumber,
			"SignatureAlgo":          certInfo.SignatureAlgo,
			"Version":                certInfo.Version,
			"IsCA":                   certInfo.IsCA,
			"KeyUsage":               certInfo.KeyUsage,
			"ExtKeyUsage":            certInfo.ExtKeyUsage,
			"CRLDistributionPoints":  certInfo.CRLDistributionPoints,
			"OCSPDistributionPoints": certInfo.OCSPDistributionPoints,
		})
	}

	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// parseCertificate парсит PEM или DER-encoded сертификат и извлекает информацию
func parseCertificate(certBytes []byte) (*CertInfo, error) {
	var cert *x509.Certificate
	var err error

	// Сначала пробуем декодировать как PEM
	block, _ := pem.Decode(certBytes)
	if block != nil {
		// Это PEM формат
		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			slog.Error("Failed to parse PEM certificate", "error", err)
			return nil, fmt.Errorf("failed to parse PEM certificate: %w", err)
		}

	} else {
		// Если не PEM, пробуем парсить как DER (бинарный формат)
		cert, err = x509.ParseCertificate(certBytes)
		if err != nil {
			slog.Error("Failed to parse certificate PEM/DER formats", "error", err)
			return nil, fmt.Errorf("failed to parse certificate PEM/DER formats): %w", err)
		}
	}

	certInfo := &CertInfo{
		Version:      cert.Version,
		SerialNumber: cert.SerialNumber.String(),
		CommonName:   cert.Subject.CommonName,
		Issuer:       cert.Issuer.CommonName,
	}

	certInfo.CRLDistributionPoints = cert.CRLDistributionPoints
	certInfo.OCSPDistributionPoints = cert.OCSPServer
	// if len(certInfo.OCSPDistributionPoints) == 0 {
	// 	certInfo.OCSPDistributionPoints = []string{""}
	// }

	// Определяем тип алгоритма и длину ключа
	certInfo.Type, certInfo.KeyLength = getKeyTypeAndLength(cert.PublicKey)

	// Время создания и истечения
	certInfo.TimeCreate = cert.NotBefore.Format("02.01.2006")
	certInfo.Expires = cert.NotAfter.Format("02.01.2006")

	// Вычисляем полный срок действия (TimeToLive)
	totalDays := int(cert.NotAfter.Sub(cert.NotBefore).Hours() / 24)
	certInfo.TimeToLive = fmt.Sprintf("%d days", totalDays)

	// Вычисляем оставшееся время (ExpiresIn)
	now := time.Now()
	if now.Before(cert.NotAfter) {
		daysLeft := int(cert.NotAfter.Sub(now).Hours() / 24)
		certInfo.ExpiresIn = fmt.Sprintf("%d days", daysLeft)
	} else {
		certInfo.ExpiresIn = "Expired"
	}

	// Тип домена
	if len(cert.DNSNames) > 1 {
		certInfo.DomainType = "Multiple"
	} else if len(cert.DNSNames) == 1 && strings.HasPrefix(cert.DNSNames[0], "*.") {
		certInfo.DomainType = "Wildcard"
	} else {
		certInfo.DomainType = "Single"
	}

	// Subject Alternative Names
	certInfo.SANs = cert.DNSNames
	// Добавляем IP адреса в SANs
	for _, ip := range cert.IPAddresses {
		certInfo.SANs = append(certInfo.SANs, ip.String())
	}

	// Subject информация
	if len(cert.Subject.Organization) > 0 {
		certInfo.Organization = cert.Subject.Organization[0]
	}
	if len(cert.Subject.OrganizationalUnit) > 0 {
		certInfo.OrgUnit = cert.Subject.OrganizationalUnit[0]
	}
	if len(cert.Subject.Locality) > 0 {
		certInfo.Locality = cert.Subject.Locality[0]
	}
	if len(cert.Subject.Province) > 0 {
		certInfo.State = cert.Subject.Province[0]
	}
	if len(cert.Subject.Country) > 0 {
		certInfo.Country = cert.Subject.Country[0]
	}

	// Email из Subject и SAN
	var emails []string

	// 1. Email из Subject DN (PKCS#9 emailAddress атрибут, OID 1.2.840.113549.1.9.1)
	for _, name := range cert.Subject.Names {
		if name.Type.String() == "1.2.840.113549.1.9.1" {
			if email, ok := name.Value.(string); ok {
				emails = append(emails, email)
			}
		}
	}

	// 2. Email из SAN (rfc822Name)
	emails = append(emails, cert.EmailAddresses...)

	// Объединяем все найденные email, убираем дубликаты
	emailMap := make(map[string]bool)
	var uniqueEmails []string
	for _, email := range emails {
		if !emailMap[email] && email != "" {
			emailMap[email] = true
			uniqueEmails = append(uniqueEmails, email)
		}
	}
	certInfo.Email = strings.Join(uniqueEmails, ", ")

	// Определяем функцию сертификата
	if cert.IsCA {
		certInfo.Function = "Certificate Authority (CA)"
		certInfo.IsCA = true
	} else {
		certInfo.Function = "End Entity Certificate"
	}

	// Алгоритм подписи
	certInfo.SignatureAlgo = cert.SignatureAlgorithm.String()

	// Key Usage
	certInfo.KeyUsage = getKeyUsage(cert.KeyUsage)

	// Extended Key Usage
	certInfo.ExtKeyUsage = getExtKeyUsage(cert.ExtKeyUsage)

	return certInfo, nil
}

// getKeyTypeAndLength возвращает тип алгоритма и длину ключа
func getKeyTypeAndLength(publicKey interface{}) (string, string) {
	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		// RSA ключ
		bitLen := pub.N.BitLen()
		return "RSA", fmt.Sprintf("%d bits", bitLen)
	case *ecdsa.PublicKey:
		// ECDSA ключ
		bitSize := pub.Curve.Params().BitSize
		return "ECDSA", fmt.Sprintf("%d bits", bitSize)
	case ed25519.PublicKey:
		// Ed25519 ключ
		return "ED25519", "256 bits"
	default:
		// Неизвестный тип ключа
		return "Unknown", "Unknown"
	}
}

// getKeyUsage возвращает строковое представление KeyUsage
func getKeyUsage(usage x509.KeyUsage) []string {
	var usages []string
	if usage&x509.KeyUsageDigitalSignature != 0 {
		usages = append(usages, "Digital Signature")
	}
	if usage&x509.KeyUsageContentCommitment != 0 {
		usages = append(usages, "Content Commitment")
	}
	if usage&x509.KeyUsageKeyEncipherment != 0 {
		usages = append(usages, "Key Encipherment")
	}
	if usage&x509.KeyUsageDataEncipherment != 0 {
		usages = append(usages, "Data Encipherment")
	}
	if usage&x509.KeyUsageKeyAgreement != 0 {
		usages = append(usages, "Key Agreement")
	}
	if usage&x509.KeyUsageCertSign != 0 {
		usages = append(usages, "Certificate Sign")
	}
	if usage&x509.KeyUsageCRLSign != 0 {
		usages = append(usages, "CRL Sign")
	}
	if usage&x509.KeyUsageEncipherOnly != 0 {
		usages = append(usages, "Encipher Only")
	}
	if usage&x509.KeyUsageDecipherOnly != 0 {
		usages = append(usages, "Decipher Only")
	}
	return usages
}

// getExtKeyUsage возвращает строковое представление ExtKeyUsage
func getExtKeyUsage(usage []x509.ExtKeyUsage) []string {
	var usages []string
	for _, u := range usage {
		switch u {
		case x509.ExtKeyUsageAny:
			usages = append(usages, "Any")
		case x509.ExtKeyUsageServerAuth:
			usages = append(usages, "TLS Web Server Authentication")
		case x509.ExtKeyUsageClientAuth:
			usages = append(usages, "TLS Web Client Authentication")
		case x509.ExtKeyUsageCodeSigning:
			usages = append(usages, "Code Signing")
		case x509.ExtKeyUsageEmailProtection:
			usages = append(usages, "Email Protection")
		case x509.ExtKeyUsageIPSECEndSystem:
			usages = append(usages, "IPSec End System")
		case x509.ExtKeyUsageIPSECTunnel:
			usages = append(usages, "IPSec Tunnel")
		case x509.ExtKeyUsageIPSECUser:
			usages = append(usages, "IPSec User")
		case x509.ExtKeyUsageTimeStamping:
			usages = append(usages, "Time Stamping")
		case x509.ExtKeyUsageOCSPSigning:
			usages = append(usages, "OCSP Signing")
		}
	}
	return usages
}
