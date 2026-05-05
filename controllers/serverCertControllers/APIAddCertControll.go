package controllers

import (
	"log/slog"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func APIAddCertsControll(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.CertsData)

		err := c.Bind().JSON(data)
		if err != nil {
			slog.Error("AddCertsControll: Error occurred", "error", err)
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		// slog.Info(data.SaveOnServer, data.ServerStatus, data.Algorithm, data.KeyLength, data.TTL, data.Domain, data.ServerId, data.Wildcard, data.Recreate, data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.AppType, data.Organization, data.OrganizationUnit, data.Email)

		if data.ServerStatus == "offline" && data.SaveOnServer {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "You can't save certificate on offline server, disable - save on server",
			})
		}

		if data.Algorithm != "RSA" && data.Algorithm != "ECDSA" && data.Algorithm != "ED25519" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid algorithm",
			})
		}

		if data.Algorithm == "RSA" {
			if data.KeyLength != 1024 && data.KeyLength != 2048 && data.KeyLength != 4096 && data.KeyLength != 8192 {
				return c.Status(400).JSON(fiber.Map{
					"status":  "error",
					"message": "Invalid key length for RSA (supported: 2048, 4096, 8192)",
				})
			}
		}
		if data.Algorithm == "ECDSA" {
			if data.KeyLength != 224 && data.KeyLength != 256 && data.KeyLength != 384 && data.KeyLength != 521 {
				return c.Status(400).JSON(fiber.Map{
					"status":  "error",
					"message": "Invalid key length for ECDSA (supported: 224, 256, 384, 521)",
				})
			}
		}
		if data.AppType != "haproxy" && data.AppType != "nginx" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid app type",
			})
		}

		if data.TTL == 0 || // TTL
			data.Domain == "" || // Domain
			data.ServerId == 0 || // ServerId
			data.CommonName == "" || // Common Name
			data.CountryName == "" || // Country Name
			data.StateProvince == "" || // State Province
			data.LocalityName == "" || // Locality Name
			data.Organization == "" || // Organization
			data.OrganizationUnit == "" || // Organization Unit
			data.Email == "" { // Email
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}

		// Генерируем сертификат в зависимости от алгоритма
		var certErr error
		var certPEM []byte
		var keyPEM []byte
		switch data.Algorithm {
		case "RSA":
			certPEM, keyPEM, certErr = crypts.GenerateRSACertificate(data, db)
			if certErr != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Error generating RSA certificate: " + certErr.Error(),
				})
			}
			if data.SaveOnServer {
				saveOnServer := crypts.NewSaveOnServer()
				err = saveOnServer.SaveOnServer(data, db, certPEM, keyPEM)
				if err != nil {
					return c.Status(400).JSON(fiber.Map{
						"status":  "error",
						"message": "Error saving certificate to server: " + err.Error(),
					})
				}
			}
		case "ECDSA":
			certPEM, keyPEM, certErr = crypts.GenerateECDSACertificate(data, db)
			if certErr != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Error generating ECDSA certificate: " + certErr.Error(),
				})
			}
			if data.SaveOnServer {
				saveOnServer := crypts.NewSaveOnServer()
				err = saveOnServer.SaveOnServer(data, db, certPEM, keyPEM)
				if err != nil {
					return c.Status(400).JSON(fiber.Map{
						"status":  "error",
						"message": "Error saving certificate to server: " + err.Error(),
					})
				}
			}
		case "ED25519":
			certPEM, keyPEM, certErr = crypts.GenerateED25519Certificate(data, db)
			if certErr != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Error generating ED25519 certificate: " + certErr.Error(),
				})
			}
			if data.SaveOnServer {
				saveOnServer := crypts.NewSaveOnServer()
				err = saveOnServer.SaveOnServer(data, db, certPEM, keyPEM)
				if err != nil {
					return c.Status(400).JSON(fiber.Map{
						"status":  "error",
						"message": "Error saving certificate to server: " + err.Error(),
					})
				}
			}
		default:
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Unsupported algorithm: " + data.Algorithm,
			})
		}
		APICertResponse := string(certPEM) + "\n" + string(keyPEM)
		return c.Send([]byte(APICertResponse))
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
