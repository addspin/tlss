package estControllers

import (
	"log/slog"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

// RevokeESTCertsController отображает страницу со списком EST-пользователей,
func RevokeESTCertsController(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("RevokeESTCertsController: database error", "error", err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		estUserList := []models.ESTUser{}
		err := db.Select(&estUserList,
			`SELECT id, username, max_uses, user_status, ttl, signing_ca_id
			 FROM est_users
			 WHERE id IN (SELECT DISTINCT est_user_id FROM est_certs WHERE cert_status = 2)`)
		if err != nil {
			slog.Error("Error getting EST users with revoked certs", "error", err)
		}

		data := fiber.Map{
			"Title":       "Revoke EST certs",
			"estUserList": estUserList,
		}

		if c.Get("HX-Request") != "" {
			if err := c.Render("revokeESTCerts-content", data, ""); err != nil {
				slog.Error("Error rendering revokeESTCerts-content", "error", err)
				return err
			}
			return nil
		}
		return c.Render("est_revoke_certs/revokeESTCerts", data)
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// ESTCertListRevokeController возвращает список отозванных EST сертификатов
func ESTCertListRevokeController(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("ESTCertListRevokeController: database error", "error", err)
	}
	defer db.Close()

	if c.Method() != "GET" {
		return c.Status(405).JSON(fiber.Map{"status": "error", "message": "Method not allowed"})
	}

	estUserId := c.Query("ESTUserId")
	certList := []models.ESTCert{}
	if estUserId != "" {
		err = db.Select(&certList,
			`SELECT id, est_user_id, common_name, algorithm, key_length,
				cert_create_time, days_left, data_revoke, reason_revoke
			 FROM est_certs WHERE est_user_id = ? AND cert_status = 2`, estUserId)
		if err != nil {
			slog.Error("ESTCertListRevokeController: select error", "error", err)
		}
	}

	for i := range certList {
		createTime, err := time.Parse(time.RFC3339, certList[i].CertCreateTime)
		if err == nil {
			certList[i].CertCreateTime = createTime.Format("02.01.2006 15:04:05")
		}
		revokeTime, err := time.Parse(time.RFC3339, certList[i].DataRevoke)
		if err == nil {
			certList[i].DataRevoke = revokeTime.Format("02.01.2006 15:04:05")
		}
	}

	return c.Render("est_revoke_certs/certESTRevokeList", fiber.Map{"certList": certList})
}
