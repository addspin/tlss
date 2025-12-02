package controllers

import (
	"log/slog"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func AddUserCertsController(c fiber.Ctx) error {
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
		switch data.Algorithm {
		case "RSA":
			_, _, certErr = crypts.GenerateUserRSACertificate(data, db)
			if certErr != nil {
				slog.Error("RSA certificate generation error", "error", certErr)
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Failed to generate RSA certificate: " + certErr.Error(),
				})
			}
		case "ED25519":
			_, _, certErr = crypts.GenerateUserED25519Certificate(data, db)
			if certErr != nil {
				slog.Error("ED25519 certificate generation error", "error", certErr)
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Failed to generate ED25519 certificate: " + certErr.Error(),
				})
			}
		case "ECDSA":
			_, _, certErr = crypts.GenerateUserECDSACertificate(data, db)
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

		return c.JSON(fiber.Map{
			"status":     "success",
			"CommonName": data.CommonName,
			"message":    "Certificate created successfully",
		})
	}
	if c.Method() == "GET" {
		entityList := []models.EntityData{}
		err := db.Select(&entityList, "SELECT id, entity_name, entity_description FROM entity")
		if err != nil {
			slog.Error("AddUserCertsController: Error occurred", "error", err)
		}
		oidList := []models.OIDData{}
		err = db.Select(&oidList, "SELECT id, oid_name, oid_description FROM oid")
		if err != nil {
			slog.Error("AddUserCertsController: Error occurred", "error", err)
		}

		data := fiber.Map{
			"Title":      "Add clients certs",
			"entityList": entityList,
			"oidList":    oidList,
		}

		// Проверяем, является ли запрос HTMX запросом
		if c.Get("HX-Request") != "" {
			err := c.Render("addUserCerts-content", data, "")
			if err != nil {
				slog.Error("Error rendering addUserCerts-content", "error", err)
				return err
			}
			return nil
		}

		return c.Render("add_user_certs/addUserCerts", data)
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// UserCertListController обрабатывает запросы на получение списка сертификатов  пользователей
func UserCertListController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		// Получаем ID сущности из запроса
		EntityId := c.Query("EntityId")
		// Получаем список сертификатов
		certList := []models.UserCertsData{}
		if EntityId != "" {
			// Если указан ID сущности, фильтруем сертификаты по сущности кроме результатов 2 - revoked
			err = db.Select(&certList, "SELECT id, entity_id, algorithm, key_length, ttl, recreate, common_name, country_name, state_province, locality_name, organization, organization_unit, email, public_key, private_key, cert_create_time, cert_expire_time, days_left, serial_number, data_revoke, reason_revoke, cert_status FROM user_certs WHERE entity_id = ? AND cert_status IN (0, 1)", EntityId)
			if err != nil {
				slog.Error("Fatal error", "error", err)
			}
		}

		// Преобразуем формат времени из RFC3339 в 02.01.2006 15:04:05
		for i := range certList {
			// Парсим время создания сертификата
			createTime, err := time.Parse(time.RFC3339, certList[i].CertCreateTime)
			if err == nil {
				certList[i].CertCreateTime = createTime.Format("02.01.2006 15:04:05")
			}

			// Парсим время истечения сертификата
			expireTime, err := time.Parse(time.RFC3339, certList[i].CertExpireTime)
			if err == nil {
				certList[i].CertExpireTime = expireTime.Format("02.01.2006 15:04:05")
			}
		}
		// Рендерим шаблон списка сертификатов
		return c.Render("add_user_certs/certUserList", fiber.Map{
			"certList": certList,
		})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
