package controllers

import (
	"fmt"
	"log"
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
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.UserCertsData)

		// c.Bind().JSON(data)

		err := c.Bind().JSON(data)
		// log.Println(data.Algorithm, data.KeyLength, data.TTL, data.Recreate, data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.Organization, data.OrganizationUnit, data.Email, data.SAN)
		if err != nil {
			log.Printf("AddUserCertsController: %v", err)
			// log.Printf("request: %s", string(c.Body()))
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.Algorithm != "RSA" && data.Algorithm != "ECDSA" && data.Algorithm != "Ed25519" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid algorithm",
			})
		}
		if data.KeyLength != 1024 && data.KeyLength != 2048 && data.KeyLength != 4096 {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid key length",
			})
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
		// Добавляем другие алгоритмы по мере необходимости
		default:
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Unsupported algorithm: " + data.Algorithm,
			})
		}
		// Если есть ошибка вернуть
		if certErr != nil {
			log.Printf("Certificate generation error: %v", certErr)
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to generate certificate: " + certErr.Error(),
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
			log.Printf("AddUserCertsController: %v", err)
		}
		oidList := []models.OIDData{}
		err = db.Select(&oidList, "SELECT id, oid_name, oid_description FROM oid")
		if err != nil {
			log.Printf("AddUserCertsController: %v", err)
		}
		log.Println("entityList", entityList)
		return c.Render("add_user_certs/addUserCerts", fiber.Map{
			"Title":      "Add clients certs",
			"entityList": entityList,
			"oidList":    oidList,
		})
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
		log.Fatal(err)
	}
	defer db.Close()
	// if c.Method() == "POST" {
	// 	// Получаем ID сущности из запроса
	// 	entityId := c.Query("entityId")
	// 	// Получаем список сертификатов
	// 	certList := []models.UserCerts{}
	// 	if entityId != "" {
	// 		// Если указан ID сущности, фильтруем сертификаты по сущности
	// 		err = db.Select(&certList, "SELECT id, entity_id, algorithm, key_length, ttl, recreate, common_name, country_name, state_province, locality_name, organization, organization_unit, email, password, public_key, private_key, cert_create_time, cert_expire_time, days_left, serial_number, data_revoke, reason_revoke, cert_status FROM user_certs WHERE entity_id = ?", entityId)
	// 		if err != nil {
	// 			log.Fatal(err)
	// 		}
	// 	}
	// 	// Рендерим шаблон списка сертификатов
	// 	return c.Render("add_user_certs/userCertList", fiber.Map{
	// 		"certList": certList,
	// 	})
	// }
	if c.Method() == "GET" {
		// Получаем ID сущности из запроса
		EntityId := c.Query("EntityId")
		// Получаем список сертификатов
		certList := []models.UserCertsData{}
		if EntityId != "" {
			// Если указан ID сущности, фильтруем сертификаты по сущности кроме результатов 2 - revoked
			err = db.Select(&certList, "SELECT id, entity_id, algorithm, key_length, ttl, recreate, common_name, country_name, state_province, locality_name, organization, organization_unit, email, public_key, private_key, cert_create_time, cert_expire_time, days_left, serial_number, data_revoke, reason_revoke, cert_status FROM user_certs WHERE entity_id = ? AND cert_status IN (0, 1)", EntityId)
			if err != nil {
				log.Fatal(err)
			}
		}
		// log.Println("certList", certList)
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
