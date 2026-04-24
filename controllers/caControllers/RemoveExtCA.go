package caControllers

import (
	"log/slog"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RemoveExtCA(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("RemoveExtCA: database connection error", "error", err)
	}
	defer db.Close()

	data := new(models.CAExtData)
	err = c.Bind().JSON(data)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Cannot parse JSON",
		})
	}
	if data.Id == 0 {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Missing certificate ID",
		})
	}

	// Находим entity_ca_id удаляемого сертификата
	var entityCAId int
	err = db.Get(&entityCAId, "SELECT entity_ca_id FROM ca_certs_ext WHERE id = ?", data.Id)
	if err != nil {
		return c.Status(404).JSON(fiber.Map{
			"status":  "error",
			"message": "Certificate not found",
		})
	}

	// Удаляем все серверные сертификаты, выпущенные этой цепочкой
	res, err := db.Exec("DELETE FROM certs WHERE signing_ca_id = ?", entityCAId)
	if err != nil {
		slog.Error("RemoveExtCA: error deleting server certs", "entity_ca_id", entityCAId, "error", err)
	} else {
		n, _ := res.RowsAffected()
		if n > 0 {
			slog.Info("RemoveExtCA: deleted server certs signed by external CA", "entity_ca_id", entityCAId, "count", n)
		}
	}

	// Удаляем все пользовательские сертификаты, выпущенные этой цепочкой
	res, err = db.Exec("DELETE FROM user_certs WHERE signing_ca_id = ?", entityCAId)
	if err != nil {
		slog.Error("RemoveExtCA: error deleting user certs", "entity_ca_id", entityCAId, "error", err)
	} else {
		n, _ := res.RowsAffected()
		if n > 0 {
			slog.Info("RemoveExtCA: deleted user certs signed by external CA", "entity_ca_id", entityCAId, "count", n)
		}
	}

	// Удаляем всю цепочку внешних CA сертификатов
	result, err := db.Exec("DELETE FROM ca_certs_ext WHERE entity_ca_id = ?", entityCAId)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Error deleting certificate chain: " + err.Error(),
		})
	}

	deleted, _ := result.RowsAffected()
	slog.Info("RemoveExtCA: deleted external CA certificate chain", "entity_ca_id", entityCAId, "deleted_count", deleted)

	// Возвращаем обновлённый список
	extCAList := []models.CAExtData{}
	err = db.Select(&extCAList, `SELECT id, entity_ca_id, type_ca, common_name, algorithm, key_length,
		cert_create_time, cert_expire_time, days_left, serial_number, cert_status
		FROM ca_certs_ext WHERE cert_status IN (0, 1)`)
	if err != nil {
		slog.Error("RemoveExtCA: error fetching ext CA list", "error", err)
	}

	for i := range extCAList {
		if extCAList[i].CertCreateTime != "" {
			if t, err := time.Parse(time.RFC3339, extCAList[i].CertCreateTime); err == nil {
				extCAList[i].CertCreateTime = t.Format("02.01.2006 15:04:05")
			}
		}
		if extCAList[i].CertExpireTime != "" {
			if t, err := time.Parse(time.RFC3339, extCAList[i].CertExpireTime); err == nil {
				extCAList[i].CertExpireTime = t.Format("02.01.2006 15:04:05")
			}
		}
	}

	return c.Render("ca/extCAList", fiber.Map{
		"extCAList": &extCAList,
	})
}
