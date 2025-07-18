package controllers

import (
	"fmt"
	"log"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/addspin/tlss/utils"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func AddCertsControll(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.CertsData)

		c.Bind().JSON(data)
		log.Println(data.SaveOnServer, data.ServerStatus, data.Algorithm, data.KeyLength, data.TTL, data.Domain, data.ServerId, data.Wildcard, data.Recreate, data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.AppType, data.Organization, data.OrganizationUnit, data.Email)

		if data.ServerStatus == "offline" && data.SaveOnServer {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "You can't save certificate on offline server, disable - save on server",
			})
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
					"message": "Ошибка генерации сертификата: " + certErr.Error(),
				})
			}
			if data.SaveOnServer {
				saveOnServer := utils.NewSaveOnServer()
				err = saveOnServer.SaveOnServer(data, db, certPEM, keyPEM)
				if err != nil {
					log.Printf("Ошибка сохранения сертификата на сервер: %v", err)
				}
			}
		default:
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Неподдерживаемый алгоритм: " + data.Algorithm,
			})
		}

		return c.JSON(fiber.Map{
			"status":  "success",
			"domain":  data.Domain,
			"message": "Certificate created successfully",
		})
	}
	if c.Method() == "GET" {
		serverList := []models.Server{}
		err := db.Select(&serverList, "SELECT id, hostname, server_status, COALESCE(cert_config_path, '') as cert_config_path FROM server")
		if err != nil {
			log.Fatal(err)
		}
		log.Println("serverList-certs", serverList)

		return c.Render("add_certs/addCerts", fiber.Map{
			"Title":      "Add certs",
			"serverList": serverList,
		})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// CertListController обрабатывает запросы на получение списка сертификатов
func CertListController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	if c.Method() == "POST" {
		// Получаем ID сервера из запроса
		serverId := c.Query("serverId")
		// Получаем список сертификатов
		certList := []models.CertsData{}
		if serverId != "" {
			// Если указан ID сервера, фильтруем сертификаты по серверу
			err = db.Select(&certList, "SELECT id, server_id, algorithm, key_length, domain, wildcard, cert_status, cert_create_time, cert_expire_time, recreate, days_left FROM certs WHERE server_id = ?", serverId)
			if err != nil {
				log.Fatal(err)
			}
		}
		// Обрабатываем wildcard домены для отображения
		if len(certList) > 0 {
			wildcard := certList[0].Wildcard
			for i := range certList {
				if wildcard {
					certList[i].Domain = "*." + certList[i].Domain
				}
			}
		}

		// Рендерим шаблон списка сертификатов
		return c.Render("add_certs/certList", fiber.Map{
			"certList": certList,
		})
	}
	if c.Method() == "GET" {
		// Получаем ID сервера из запроса
		serverId := c.Query("serverId")
		// Получаем список сертификатов
		certList := []models.CertsData{}

		if serverId != "" {
			// Если указан ID сервера, фильтруем сертификаты по серверу кроме результатов 2 - revoked
			err = db.Select(&certList, "SELECT id, server_id, algorithm, key_length, domain, wildcard, cert_status, cert_create_time, cert_expire_time, recreate, days_left FROM certs WHERE server_id = ? AND cert_status IN (0, 1)", serverId)
			if err != nil {
				log.Fatal(err)
			}
		}
		// Обрабатываем wildcard домены для отображения
		if len(certList) > 0 {
			// wildcard := certList[0].Wildcard
			for i := range certList {
				if certList[i].Wildcard {
					certList[i].Domain = "*." + certList[i].Domain
				}
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
		return c.Render("add_certs/certList", fiber.Map{
			"certList": certList,
		})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
