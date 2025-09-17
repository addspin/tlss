package controllers

import (
	"fmt"
	"log"

	"github.com/addspin/tlss/check"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

const (
	certStatusValid   = 0
	certStatusExpired = 1
	certStatusRevoked = 2
)

func Overview(c fiber.Ctx) error {

	//---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "GET" {
		serverList := []models.Server{}

		err := db.Select(&serverList, "SELECT id, hostname, COALESCE(cert_config_path, '') as cert_config_path, server_status FROM server WHERE cert_config_path NOT NULL")
		if err != nil {
			log.Fatal(err)
		}

		// serverCertId := []models.CertsData{}
		// err = db.Select(&serverCertId, "SELECT * FROM certs where cert_status = ?", certStatusValid)
		// if err != nil {
		// 	log.Fatal(err)
		// }

		// serverHostname := []models.Server{}
		// err = db.Select(&serverHostname, "SELECT hostname FROM server" )
		// if err != nil {
		// 	log.Fatal(err)
		// }

		caCertList := []models.CAData{}
		err = db.Select(&caCertList, "SELECT type_ca, days_left, data_revoke  FROM ca_certs WHERE cert_status = ?", certStatusValid)
		if err != nil {
			log.Fatal(err)
		}

		serverCertList := []models.CertsData{}
		err = db.Select(&serverCertList, "SELECT * FROM certs")
		if err != nil {
			log.Fatal(err)
		}
		serverCertCount := 0
		serverCertExpired := 0
		serverCertRevoked := 0

		for cert := range serverCertList {
			if serverCertList[cert].CertStatus == certStatusValid {
				serverCertCount++
			}
		}
		for cert := range serverCertList {
			if serverCertList[cert].CertStatus == certStatusExpired {
				serverCertExpired++
			}
		}
		for cert := range serverCertList {
			if serverCertList[cert].CertStatus == certStatusRevoked {
				serverCertRevoked++
			}
		}

		userCertList := []models.UserCertsData{}
		err = db.Select(&userCertList, "SELECT * FROM user_certs")
		if err != nil {
			log.Fatal(err)
		}

		userCertCount := 0
		userCertExpired := 0
		userCertRevoked := 0

		for cert := range userCertList {
			if userCertList[cert].CertStatus == certStatusValid {
				userCertCount++
			}
			if userCertList[cert].CertStatus == certStatusExpired {
				userCertExpired++
			}
			if userCertList[cert].CertStatus == certStatusRevoked {
				userCertRevoked++
			}
		}

		recreateCertCheck := check.Monitors.RecreateCertStatus
		validCertsCheck := check.Monitors.CheckValidCertsStatus
		tcpCheck := check.Monitors.CheckTCPStatus
		taskList := map[string]bool{"Recreate certs": recreateCertCheck, "Valid certs": validCertsCheck, "Server check": tcpCheck}

		// log.Println("serverList", serverList)
		return c.Render("overview/overview", fiber.Map{
			"Title":             "Overview",
			"serverList":        &serverList,
			"taskList":          &taskList,
			"caCertList":        &caCertList,
			"userCertList":      &userCertList,
			"userCertCount":     userCertCount,
			"userCertExpired":   userCertExpired,
			"userCertRevoked":   userCertRevoked,
			"serverCertCount":   serverCertCount,
			"serverCertExpired": serverCertExpired,
			"serverCertRevoked": serverCertRevoked,
			"serverCertList":    &serverCertList,
			// "serverHostname":    serverHostname,
		})
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
