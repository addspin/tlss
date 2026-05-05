package controllers

import (
	"log/slog"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func APIAddUserCertsController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}

	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.UserCertsData)

		// c.Bind().JSON(data)

		err := c.Bind().JSON(data)
		// slog.Info(data.Algorithm, data.KeyLength, data.TTL, data.Recreate, data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.Organization, data.OrganizationUnit, data.Email, data.SAN)
		if err != nil {
			slog.Error("AddUserCertsController: Error occurred", "error", err)

			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
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
					"message": "Invalid key length for ECDSA (supported: 256, 384, 521)",
				})
			}
		}

		if data.TTL == 0 || // TTL
			data.EntityId == 0 || // EntityId
			data.CommonName == "" || // Common Name
			data.CountryName == "" || // Country Name
			data.StateProvince == "" || // State Province
			data.LocalityName == "" || // Locality Name
			data.Organization == "" || // Organization
			data.OrganizationUnit == "" || // Organization Unit
			data.Email == "" || // Email
			data.Password == "" { // Password
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
			certPEM, keyPEM, certErr = crypts.GenerateUserRSACertificate(data, db)
			if certErr != nil {
				slog.Error("RSA certificate generation error", "error", certErr)
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Failed to generate RSA certificate: " + certErr.Error(),
				})
			}
		case "ED25519":
			certPEM, keyPEM, certErr = crypts.GenerateUserED25519Certificate(data, db)
			if certErr != nil {
				slog.Error("ED25519 certificate generation error", "error", certErr)
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Failed to generate ED25519 certificate: " + certErr.Error(),
				})
			}
		case "ECDSA":
			certPEM, keyPEM, certErr = crypts.GenerateUserECDSACertificate(data, db)
			if certErr != nil {
				slog.Error("ECDSA certificate generation error", "error", certErr)
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Failed to generate ECDSA certificate: " + certErr.Error(),
				})
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
