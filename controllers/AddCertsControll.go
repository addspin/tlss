package controllers

import (
	"fmt"
	"log"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
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
		log.Println(data.Algorithm, data.KeyLength, data.TTL, data.Domain, data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.Organization, data.OrganizationUnit, data.Email, data.Password, data.CaName, data.CaKey, data.CertName, data.CertCreateTime, data.CertExpireTime)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.Algorithm == "" ||
			data.KeyLength == 0 ||
			data.TTL == 0 ||
			data.Domain == "" ||
			data.CommonName == "" ||
			data.CountryName == "" ||
			data.StateProvince == "" ||
			data.LocalityName == "" ||
			data.Organization == "" ||
			data.OrganizationUnit == "" ||
			data.Email == "" ||
			data.Password == "" ||
			data.CaName == "" ||
			data.CaKey == "" ||
			data.CertName == "" ||
			data.CertCreateTime == "" ||
			data.CertExpireTime == "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}
		//create certs
		// ca, err := crypts.CreateCA(data.CaName, data.CaKey, data.TTL, data.Domain, data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.Organization, data.OrganizationUnit, data.Email, data.Password)
	}
	// if c.Method() == "GET" {
	// 	serverList := []models.Server{}
	// 	err := db.Select(&serverList, "SELECT id, hostname, cert_config_path, server_status FROM server")
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}
	// 	log.Println("serverList", serverList)
	// 	return c.Render("add_server/addServer", fiber.Map{
	// 		"Title":      "Add server",
	// 		"serverList": &serverList,
	// 	})
	// }
	// serverList := []models.Server{}
	// error := db.Select(&serverList, "SELECT id, hostname, cert_config_path, server_status FROM server")
	// if error != nil {
	// 	log.Fatal(err)
	// }
	// log.Println("serverList", serverList)
	return c.Render("add_certs/addCerts", fiber.Map{
		"Title": "Add certs",
	})
}
