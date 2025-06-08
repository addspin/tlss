package controllers

import (
	"fmt"
	"log"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func RevokeUserCertsController(c fiber.Ctx) error {
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
		entityList := []models.EntityData{}
		err := db.Select(&entityList, "SELECT id, entity_name, entity_description FROM entity")
		if err != nil {
			log.Fatal(err)
		}
		log.Println("entityList-certs", entityList)

		return c.Render("user_revoke_certs/revokeUserCerts", fiber.Map{
			"Title":      "Revoke users certs",
			"entityList": entityList,
		})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// UserCertListRevokeController обрабатывает запросы на получение списка отозванных сертификатов
func UserCertListRevokeController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		// Получаем ID сервера из запроса
		EntityId := c.Query("EntityId")
		// Получаем список сертификатов
		certList := []models.UserCertsData{}
		if EntityId != "" {
			// Если указан ID сервера, фильтруем сертификаты по серверу кроме результатов 2 - revoked
			err = db.Select(&certList, "SELECT id, entity_id, common_name, algorithm, key_length, cert_create_time, days_left, data_revoke, reason_revoke FROM user_certs WHERE entity_id = ? AND cert_status IN (2)", EntityId)
			if err != nil {
				log.Fatal(err)
			}
		}

		// Преобразуем формат времени из RFC3339 в 02.01.2006 15:04:05
		for i := range certList {
			// Парсим время создания сертификата
			createTime, err := time.Parse(time.RFC3339, certList[i].CertCreateTime)
			if err == nil {
				certList[i].CertCreateTime = createTime.Format("02.01.2006 15:04:05")
			}

			// Парсим время отзыва сертификата
			revokeTime, err := time.Parse(time.RFC3339, certList[i].DataRevoke)
			if err == nil {
				certList[i].DataRevoke = revokeTime.Format("02.01.2006 15:04:05")
			}
		}
		// Рендерим шаблон списка сертификатов
		return c.Render("user_revoke_certs/certUserRevokeList", fiber.Map{
			"certList": certList,
		})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
