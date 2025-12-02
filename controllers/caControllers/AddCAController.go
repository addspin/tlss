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

func AddCAController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.CAData)

		err := c.Bind().JSON(data)
		// slog.Info(data.Algorithm, data.KeyLength, data.TTL, data.Recreate, data.CommonName, data.CountryName, data.StateProvince, data.LocalityName, data.Organization, data.OrganizationUnit, data.Email, data.SAN)
		if err != nil {
			slog.Error("AddCAController: Error binding JSON", "error", err)
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}

		if data.TTL == 0 || // TTL
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
		data.ReasonRevoke = "superseded"
		certErr := CreateCACertRSA(data, db)
		if certErr != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to generate certificate: " + certErr.Error(),
			})
		}

		// switch data.TypeCA {
		// case "Root":
		// 	certErr = RevokeCACert(c, data)
		// case "Sub":
		// 	certErr = crypts.GenerateRSASubCA(data, db)
		// // Добавляем другие алгоритмы по мере необходимости
		// default:
		// 	return c.Status(400).JSON(fiber.Map{
		// 		"status":  "error",
		// 		"message": "Unsupported algorithm: " + data.Algorithm,
		// 	})
		// }
		// Если есть ошибка вернуть
		// if certErr != nil {
		// 	slog.Info("Certificate generation error: %v", certErr)
		// 	return c.Status(500).JSON(fiber.Map{
		// 		"status":  "error",
		// 		"message": "Failed to generate certificate: " + certErr.Error(),
		// 	})
		// }

		return c.JSON(fiber.Map{
			"status":     "success",
			"CommonName": data.CommonName,
			"message":    "Certificate created successfully",
		})
	}

	if c.Method() == "GET" {
		data := fiber.Map{
			"Title":    "Add CA",
			"certList": []models.CAData{}, // Передаем пустой список для корректного отображения шаблона
		}

		// Проверяем, является ли запрос HTMX запросом
		if c.Get("HX-Request") != "" {
			err := c.Render("addCACerts-content", data, "")
			if err != nil {
				slog.Error("Error rendering addCACerts-content", "error", err)
				return err
			}
			return nil
		}

		return c.Render("ca/addCACerts", data)
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// CACertListController обрабатывает запросы на получение списка сертификатов  пользователей
func CACertListController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		// Получаем список сертификатов
		certList := []models.CAData{}
		// Получаем список сертификатов с фильтрацией по статусу 0 - valid, 1 - expired
		err = db.Select(&certList, "SELECT id, algorithm, type_ca, key_length, ttl, recreate, common_name, country_name, state_province, locality_name, organization, organization_unit, email, cert_create_time, cert_expire_time, days_left, data_revoke, reason_revoke, cert_status FROM ca_certs WHERE cert_status IN (0, 1)")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}
		// Преобразуем формат времени из RFC3339 в 02.01.2006 15:04:05
		for i := range certList {

			// Парсим время создания сертификата
			if certList[i].CertCreateTime != "" {
				createTime, err := time.Parse(time.RFC3339, certList[i].CertCreateTime)
				if err != nil {
					slog.Error("DEBUG: Error parsing CertCreateTime", "error", err)
				} else {
					certList[i].CertCreateTime = createTime.Format("02.01.2006 15:04:05")
				}
			}

			// Парсим время истечения сертификата
			if certList[i].CertExpireTime != "" {
				expireTime, err := time.Parse(time.RFC3339, certList[i].CertExpireTime)
				if err != nil {
					slog.Error("DEBUG: Error parsing CertExpireTime", "error", err)
				} else {
					certList[i].CertExpireTime = expireTime.Format("02.01.2006 15:04:05")
				}
			}
		}
		return c.Render("ca/certCAList", fiber.Map{
			"Title":    "CA list",
			"certList": certList,
		})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
