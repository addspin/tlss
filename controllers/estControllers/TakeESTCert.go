package estControllers

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
	"software.sslmate.com/src/go-pkcs12"
)

// TakeESTCert обрабатывает скачивание EST сертификата
func TakeESTCert(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("TakeESTCert: database error", "error", err)
	}
	defer db.Close()

	if c.Method() != "GET" {
		return c.Status(405).JSON(fiber.Map{
			"status":  "error",
			"message": "Method not allowed",
		})
	}

	estUserId := c.Query("ESTUserId")
	id := c.Query("id")
	format := c.Query("format")
	if estUserId == "" || id == "" || format == "" {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Missing query params: ESTUserId, id, format",
		})
	}

	// Извлекаем сертификат
	var cert models.ESTCert
	err = db.Get(&cert, `SELECT common_name, public_key, private_key, password, signing_ca_id
		FROM est_certs WHERE id = ? AND est_user_id = ?`, id, estUserId)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": fmt.Sprintf("Failed to get EST certificate: %v", err),
		})
	}

	// Расшифровываем приватный ключ
	aes := crypts.Aes{}
	decryptedKey, err := aes.Decrypt([]byte(cert.PrivateKey), crypts.AesSecretKey.Key)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Error decrypting private key",
		})
	}

	// Извлекаем цепочку CA для архива (Sub + Root для Core, или внешний CA)
	var subCACert, rootCACert string
	if cert.SigningCAId == 0 {
		// Core CA
		err = db.Get(&subCACert, "SELECT public_key FROM ca_certs WHERE type_ca = 'Sub' AND cert_status = 0")
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to get Sub CA",
			})
		}
		err = db.Get(&rootCACert, "SELECT public_key FROM ca_certs WHERE type_ca = 'Root' AND cert_status = 0")
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to get Root CA",
			})
		}
	}

	if format == "zip" {
		var buf bytes.Buffer
		zipWriter := zip.NewWriter(&buf)

		// Сертификат
		certFile, _ := zipWriter.Create(cert.CommonName + ".pem")
		certFile.Write([]byte(cert.PublicKey))

		// Приватный ключ
		keyFile, _ := zipWriter.Create(cert.CommonName + ".key")
		keyFile.Write(decryptedKey)

		// CA цепочка (только для Core)
		if cert.SigningCAId == 0 {
			subFile, _ := zipWriter.Create("sub_ca_tlss.pem")
			subFile.Write([]byte(subCACert))
			rootFile, _ := zipWriter.Create("root_ca_tlss.pem")
			rootFile.Write([]byte(rootCACert))
		}

		if err = zipWriter.Close(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error closing archive",
			})
		}

		fileName := fmt.Sprintf("est_cert_%s.zip", cert.CommonName)
		c.Set("Content-Type", "application/zip")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
		c.Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
		return c.Send(buf.Bytes())
	}

	if format == "pkcs12" || format == "pkcs12-legacy" {
		// Расшифровываем пароль
		decryptedPassword, err := aes.Decrypt([]byte(cert.Password), crypts.AesSecretKey.Key)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error decrypting password",
			})
		}

		// Парсим сертификат
		certBlock, _ := pem.Decode([]byte(cert.PublicKey))
		if certBlock == nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to decode certificate PEM",
			})
		}
		x509Cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": fmt.Sprintf("Failed to parse certificate: %v", err),
			})
		}

		// Парсим приватный ключ
		keyBlock, _ := pem.Decode(decryptedKey)
		if keyBlock == nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to decode private key PEM",
			})
		}
		var privKey any
		switch keyBlock.Type {
		case "RSA PRIVATE KEY":
			privKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		case "EC PRIVATE KEY":
			privKey, err = x509.ParseECPrivateKey(keyBlock.Bytes)
		case "PRIVATE KEY":
			privKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		default:
			err = fmt.Errorf("unsupported private key type: %s", keyBlock.Type)
		}
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": fmt.Sprintf("Failed to parse private key: %v", err),
			})
		}

		// Цепочка
		var chain []*x509.Certificate
		if cert.SigningCAId == 0 && subCACert != "" {
			subBlock, _ := pem.Decode([]byte(subCACert))
			if subBlock != nil {
				if subX509, err := x509.ParseCertificate(subBlock.Bytes); err == nil {
					chain = append(chain, subX509)
				}
			}
		}

		var p12Data []byte
		if format == "pkcs12" {
			p12Data, err = pkcs12.Modern.Encode(privKey, x509Cert, chain, string(decryptedPassword))
		} else {
			p12Data, err = pkcs12.Legacy.Encode(privKey, x509Cert, chain, string(decryptedPassword))
		}
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": fmt.Sprintf("Failed to create PKCS12: %v", err),
			})
		}

		fileName := fmt.Sprintf("est_cert_%s.p12", cert.CommonName)
		c.Set("Content-Type", "application/x-pkcs12")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
		c.Set("Content-Length", fmt.Sprintf("%d", len(p12Data)))
		return c.Send(p12Data)
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Unsupported format",
	})
}
