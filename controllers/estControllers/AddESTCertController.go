package estControllers

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

// AddESTCertController создание EST сертификата
func AddESTCertController(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("AddESTCertController: database error", "error", err)
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Database error"})
	}
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.ESTCert)
		if err := c.Bind().JSON(data); err != nil {
			slog.Error("AddESTCertController: Cannot parse JSON", "error", err)
			return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Cannot parse JSON"})
		}

		// Валидация алгоритма
		if data.Algorithm != "RSA" && data.Algorithm != "ECDSA" && data.Algorithm != "ED25519" {
			return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Invalid algorithm"})
		}
		if data.Algorithm == "RSA" {
			if data.KeyLength != 2048 && data.KeyLength != 4096 && data.KeyLength != 8192 {
				return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Invalid key length for RSA (2048, 4096, 8192)"})
			}
		}
		if data.Algorithm == "ECDSA" {
			if data.KeyLength != 256 && data.KeyLength != 384 && data.KeyLength != 521 {
				return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Invalid key length for ECDSA (256, 384, 521)"})
			}
		}

		// Обязательные поля
		if data.TTL == 0 ||
			data.ESTUserId == 0 ||
			data.CommonName == "" ||
			data.Password == "" {
			return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Missing required fields"})
		}

		// Генерация по алгоритму
		var certErr error
		switch data.Algorithm {
		case "RSA":
			_, _, certErr = crypts.GenerateESTRSACertificate(data, db)
		case "ECDSA":
			_, _, certErr = crypts.GenerateESTECDSACertificate(data, db)
		case "ED25519":
			_, _, certErr = crypts.GenerateESTED25519Certificate(data, db)
		default:
			return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Unsupported algorithm: " + data.Algorithm})
		}
		if certErr != nil {
			slog.Error("EST cert generation error", "error", certErr)
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to generate EST certificate: " + certErr.Error(),
			})
		}

		return c.JSON(fiber.Map{
			"status":     "success",
			"CommonName": data.CommonName,
			"message":    "EST certificate created successfully",
		})
	}

	if c.Method() == "GET" {
		// Список EST-пользователей
		estUserList := []models.ESTUser{}
		err := db.Select(&estUserList, `SELECT id, username, max_uses, user_status, ttl, signing_ca_id
			FROM est_users ORDER BY id DESC`)
		if err != nil {
			slog.Error("AddESTCertController: Error fetching EST users", "error", err)
		}

		// Список внешних CA
		entityCAList := []models.EntityCAData{}
		err = db.Select(&entityCAList, "SELECT id, entity_ca_name, entity_ca_description FROM entity_ca")
		if err != nil {
			slog.Error("AddESTCertController: Error fetching entity CA list", "error", err)
		}

		data := fiber.Map{
			"Title":        "Add EST certs",
			"estUserList":  estUserList,
			"entityCAList": entityCAList,
		}

		if c.Get("HX-Request") != "" {
			if err := c.Render("addESTCerts-content", data, ""); err != nil {
				slog.Error("Error rendering addESTCerts-content", "error", err)
				return err
			}
			return nil
		}
		return c.Render("est/addESTCerts", data)
	}

	return c.Status(405).JSON(fiber.Map{"status": "error", "message": "Method not allowed"})
}

// ESTCertListController возвращает список EST сертификатов
func ESTCertListController(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Database error"})
	}
	defer db.Close()

	if c.Method() != "GET" {
		return c.Status(405).JSON(fiber.Map{"status": "error", "message": "Method not allowed"})
	}

	estUserId := c.Query("ESTUserId")
	certList := []models.ESTCert{}

	if estUserId != "" && estUserId != "all" {
		err = db.Select(&certList, `SELECT id, est_user_id, serial_number, signing_ca_id,
			common_name, san, algorithm, key_length, ttl,
			cert_create_time, cert_expire_time, days_left,
			data_revoke, reason_revoke, cert_status
			FROM est_certs WHERE est_user_id = ? AND cert_status IN (0, 1)
			ORDER BY id DESC`, estUserId)
		if err != nil {
			slog.Error("ESTCertListController: select error", "error", err)
		}
	}
	if estUserId == "all" {
		err = db.Select(&certList, `SELECT id, est_user_id, serial_number, signing_ca_id,
			common_name, san, algorithm, key_length, ttl,
			cert_create_time, cert_expire_time, days_left,
			data_revoke, reason_revoke, cert_status
			FROM est_certs WHERE cert_status IN (0, 1)
			ORDER BY id DESC`)
		if err != nil {
			slog.Error("ESTCertListController: select error", "error", err)
		}
	}

	// Преобразуем формат времени из RFC3339
	for i := range certList {
		createTime, err := time.Parse(time.RFC3339, certList[i].CertCreateTime)
		if err == nil {
			certList[i].CertCreateTime = createTime.Format("02.01.2006 15:04:05")
		}
		expireTime, err := time.Parse(time.RFC3339, certList[i].CertExpireTime)
		if err == nil {
			certList[i].CertExpireTime = expireTime.Format("02.01.2006 15:04:05")
		}
	}

	return c.Render("est/certESTList", fiber.Map{"certList": certList})
}
