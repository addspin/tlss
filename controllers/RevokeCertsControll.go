package controllers

import (
	"fmt"
	"log"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func RevokeCertsController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	// if c.Method() == "POST" {
	// 	data := new(models.Certs)

	// 	c.Bind().JSON(data)
	// 	// log.Println(data.Algorithm, data.KeyLength, data.TTL, data.Domain, data.ServerId, data.Wildcard, data.Recreate, data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.Organization, data.OrganizationUnit, data.Email)

	// 	err := c.Bind().JSON(data)
	// 	if err != nil {
	// 		return c.Status(400).JSON(
	// 			fiber.Map{"status": "error",
	// 				"message": "Cannot parse JSON!",
	// 				"data":    err},
	// 		)
	// 	}

	// }
	if c.Method() == "GET" {
		serverList := []models.Server{}
		err := db.Select(&serverList, "SELECT id, hostname, server_status FROM server")
		if err != nil {
			log.Fatal(err)
		}
		log.Println("serverList-certs", serverList)

		return c.Render("revoke_certs/revokeCerts", fiber.Map{
			"Title":      "Revoke certs",
			"serverList": serverList,
		})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// CertListRevokeController обрабатывает запросы на получение списка отозванных сертификатов
func CertListRevokeController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		// Получаем ID сервера из запроса
		serverId := c.Query("serverId")
		// Получаем список сертификатов
		certList := []models.Certs{}
		if serverId != "" {
			// Если указан ID сервера, фильтруем сертификаты по серверу кроме результатов 2 - revoked
			err = db.Select(&certList, "SELECT id, server_id, algorithm, key_length, domain, wildcard, cert_create_time, days_left, data_revoke, reason_revoke FROM certs WHERE server_id = ? AND cert_status IN (2)", serverId)
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
		return c.Render("revoke_certs/certRevokeList", fiber.Map{
			"certList": certList,
		})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
