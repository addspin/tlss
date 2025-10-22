package caControllers

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func RevokeCACertsController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "GET" {
		certList := []models.CAData{}
		err := db.Select(&certList, "SELECT id, common_name, type_ca, algorithm, key_length, ttl, cert_create_time, cert_expire_time, days_left, data_revoke, reason_revoke FROM ca_certs WHERE cert_status IN (2)")
		if err != nil {
			slog.Error("Fatal error", "error", err)
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
		return c.Render("ca_revoke_certs/revokeCACerts", fiber.Map{
			"Title":    "Revoke CA certs",
			"certList": certList,
		})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
