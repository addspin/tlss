package controllers

import (
	"log/slog"
	"time"

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
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		// Получаем список серверов, у которых есть отозванные сертификаты (cert_status = 2)
		serverList := []models.Server{}
		err = db.Select(&serverList,
			`SELECT id, hostname, server_status, COALESCE(cert_config_path, '') as cert_config_path 
			 FROM server 
			 WHERE id IN (SELECT DISTINCT server_id FROM certs WHERE cert_status = 2)`)
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}
		slog.Info("Servers with revoked certs found", "count", len(serverList))

		data := fiber.Map{
			"Title":      "Revoke certs",
			"serverList": serverList,
		}

		// Проверяем, является ли запрос HTMX запросом
		if c.Get("HX-Request") != "" {
			err := c.Render("revokeCerts-content", data, "")
			if err != nil {
				slog.Error("Error rendering revokeCerts-content", "error", err)
				return err
			}
			return nil
		}

		return c.Render("revoke_certs/revokeCerts", data)
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
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		// Получаем ID сервера из запроса
		ServerId := c.Query("ServerId")
		// Получаем список сертификатов
		certList := []models.CertsData{}
		if ServerId != "" {
			// Если указан ID сервера, фильтруем сертификаты по серверу кроме результатов 2 - revoked
			err = db.Select(&certList, "SELECT id, server_id, algorithm, key_length, ttl, domain, wildcard, recreate, save_on_server, common_name, country_name, state_province, locality_name, app_type, organization, organization_unit, email, public_key, private_key, cert_create_time, cert_expire_time, days_left, serial_number, data_revoke, reason_revoke, cert_status FROM certs WHERE server_id = ? AND cert_status IN (2)", ServerId)
			if err != nil {
				slog.Error("Fatal error", "error", err)
			}
		}
		// Обрабатываем wildcard домены для отображения
		for i := range certList {
			wildcard := certList[i].Wildcard
			if wildcard {
				certList[i].Domain = "*." + certList[i].Domain
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
		return c.Render("revoke_certs/certRevokeList", fiber.Map{
			"certList": certList,
		})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
