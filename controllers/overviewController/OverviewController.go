package controllers

import (
	"log/slog"

	"github.com/addspin/tlss/check"
	"github.com/addspin/tlss/middleware"
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
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		serverList := []models.Server{}

		err := db.Select(&serverList, "SELECT id, hostname, COALESCE(cert_config_path, '') as cert_config_path, server_status FROM server WHERE cert_config_path NOT NULL")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}

		caCertList := []models.CAData{}
		err = db.Select(&caCertList, "SELECT type_ca, days_left, data_revoke  FROM ca_certs WHERE cert_status = ?", certStatusValid)
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}

		serverCertList := []models.CertsData{}
		err = db.Select(&serverCertList, "SELECT * FROM certs")
		if err != nil {
			slog.Error("Fatal error", "error", err)
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
			slog.Error("Fatal error", "error", err)
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

		data := fiber.Map{
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
		}

		// Проверяем, является ли запрос HTMX запросом
		if c.Get("HX-Request") != "" {
			// Используем имя шаблона из {{define "overview-content"}} напрямую
			err := c.Render("overview-content", data, "")
			if err != nil {
				slog.Error("Error rendering overview-content", "error", err)
				return err
			}
			return nil
		}

		// Проверяем авторизацию и выбираем нужный шаблон
		isAuthenticated := middleware.IsAuthenticated(c)

		if isAuthenticated {
			// Авторизованный пользователь - показываем полное меню
			slog.Info("Authenticated user - rendering full page with auth menu")
			return c.Render("overview/overview", data)
		} else {
			// Неавторизованный пользователь - показываем публичное меню
			slog.Info("Public user - rendering page with public menu")
			return c.Render("overview/overview-public", data)
		}
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
