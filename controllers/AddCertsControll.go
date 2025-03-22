package controllers

import (
	"fmt"
	"log"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
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
		data := new(models.Certs)

		c.Bind().JSON(data)
		log.Println(data.Algorithm, data.KeyLength, data.TTL, data.Domain, data.ServerId, data.Wildcard, data.Recreate, data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.Organization, data.OrganizationUnit, data.Email)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}

		if data.Algorithm == "" || // Type
			data.KeyLength == 0 || // Lenght
			data.TTL == 0 || // TTL
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
		switch data.Algorithm {
		case "RSA":
			certErr = crypts.GenerateRSACertificate(data, db)
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
		// // Если нет ошибки вернуть
		// serverList := []models.Server{}
		// err = db.Select(&serverList, "SELECT id, hostname, server_status FROM server")
		// if err != nil {
		// 	log.Fatal(err)
		// }
		// log.Println("serverList-certs", serverList)
		// onlineServers := []models.Server{}
		// for _, list := range serverList {
		// 	// Записываем только онлайн сервера, чтобы не было ошибки при добавлении сертификата
		// 	if list.ServerStatus == "online" {
		// 		onlineServers = append(onlineServers, list)
		// 		log.Println("onlineServerList-certs", onlineServers)
		// 	}
		// }
		// return c.Render("add_certs/addCerts", fiber.Map{
		// 	"Title":      "Add certs",
		// 	"serverList": onlineServers,
		// })
		// Если нет ошибки, вернуть JSON с успешным статусом
		return c.JSON(fiber.Map{
			"status":  "success",
			"domain":  data.Domain,
			"message": "Certificate created successfully",
		})
	}
	if c.Method() == "GET" {
		serverList := []models.Server{}
		err := db.Select(&serverList, "SELECT id, hostname, server_status FROM server")
		if err != nil {
			log.Fatal(err)
		}
		log.Println("serverList-certs", serverList)
		onlineServers := []models.Server{}
		for _, list := range serverList {
			// Записываем только онлайн сервера, чтобы не было ошибки при добавлении сертификата
			if list.ServerStatus == "online" {
				onlineServers = append(onlineServers, list)
				log.Println("onlineServerList-certs", onlineServers)
			}
		}

		return c.Render("add_certs/addCerts", fiber.Map{
			"Title":      "Add certs",
			"serverList": onlineServers,
		})
	}
	serverList := []models.Server{}
	error := db.Select(&serverList, "SELECT id, server_id, hostname, server_status FROM server")
	if error != nil {
		log.Fatal(err)
	}
	onlineServers := []models.Server{}
	for _, list := range serverList {
		if list.ServerStatus == "online" {
			onlineServers = append(onlineServers, list)
			log.Println("serverList-certs", onlineServers)
		}
	}
	return c.Render("add_certs/addCerts", fiber.Map{
		"Title":      "Add certs",
		"serverList": onlineServers,
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
		certList := []models.Certs{}
		if serverId != "" {
			// Если указан ID сервера, фильтруем сертификаты по серверу
			err = db.Select(&certList, "SELECT id, server_id, algorithm, key_length, domain, wildcard, cert_status, cert_create_time, cert_expire_time, recreate, days_left FROM certs WHERE server_id = ?", serverId)
			if err != nil {
				log.Fatal(err)
			}
		}
		// Обрабатываем wildcard домены для отображения
		for i := range certList {
			if certList[i].Wildcard {
				certList[i].Domain = "*." + certList[i].Domain
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
		certList := []models.Certs{}
		if serverId != "" {
			// Если указан ID сервера, фильтруем сертификаты по серверу кроме результатов 2 - revoked
			err = db.Select(&certList, "SELECT id, server_id, algorithm, key_length, domain, wildcard, cert_status, cert_create_time, cert_expire_time, recreate, days_left FROM certs WHERE server_id = ? AND cert_status IN (0, 1)", serverId)
			if err != nil {
				log.Fatal(err)
			}
		}
		// Обрабатываем wildcard домены для отображения
		for i := range certList {
			if certList[i].Wildcard {
				certList[i].Domain = "*." + certList[i].Domain
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
