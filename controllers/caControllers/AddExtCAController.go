package caControllers

import (
	"fmt"
	"io"
	"log/slog"
	"mime/multipart"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func AddExtCAController(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("ExtCAController: database connection error", "error", err)
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Database connection error"})
	}
	defer db.Close()

	if c.Method() == "POST" {
		return handleExtCAUpload(c, db)
	}

	entityCAList := []models.EntityCAData{}
	err = db.Select(&entityCAList, "SELECT id, TRIM(entity_ca_name) as entity_ca_name, TRIM(entity_ca_description) as entity_ca_description FROM entity_ca")
	if err != nil {
		slog.Error("ExtCAController: error fetching entity CA list", "error", err)
	}

	extCAList := []models.CAExtData{}
	err = db.Select(&extCAList, `SELECT id, entity_ca_id, type_ca, common_name, algorithm, key_length,
		cert_create_time, cert_expire_time, days_left, serial_number, cert_status
		FROM ca_certs_ext WHERE cert_status IN (0, 1)`)
	if err != nil {
		slog.Error("ExtCAController: error fetching ext CA list", "error", err)
	}

	// Форматируем даты для отображения
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

	data := fiber.Map{
		"Title":        "External CA",
		"entityCAList": &entityCAList,
		"extCAList":    &extCAList,
	}

	if c.Get("HX-Request") != "" {
		return c.Render("extCA-content", data, "")
	}
	return c.Render("ca/extCA", data)
}

func handleExtCAUpload(c fiber.Ctx, db *sqlx.DB) error {
	// Получаем entity_ca_id
	entityCAId := c.FormValue("entity_ca_id")
	if entityCAId == "" {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Entity CA is required",
		})
	}

	var entityId int
	_, err := fmt.Sscanf(entityCAId, "%d", &entityId)
	if err != nil || entityId == 0 {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Invalid Entity CA ID",
		})
	}

	// Проверяем что entity_ca существует
	var exists bool
	err = db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM entity_ca WHERE id = ?)", entityId)
	if err != nil || !exists {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Entity CA not found",
		})
	}

	// Получаем multipart form
	form, err := c.MultipartForm()
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to parse multipart form",
		})
	}

	files := form.File["ca_files"]
	if len(files) < 2 {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "At least 2 files required (certificate + private key)",
		})
	}

	// Читаем все файлы
	fileData := make([][]byte, 0, len(files))
	for _, fh := range files {
		data, err := readExtCAFormFile(fh)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to read file: " + fh.Filename,
			})
		}
		fileData = append(fileData, data)
	}

	// Парсим PEM-файлы
	certs, keys, err := crypts.ParsePEMFiles(fileData)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": err.Error(),
		})
	}

	if len(keys) == 0 {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "No private keys found in uploaded files. At least one key is required",
		})
	}

	// Сопоставляем ключи с сертификатами
	pairs := crypts.MatchKeysToCerts(certs, keys)

	// Строим записи для БД
	records, err := crypts.BuildCAExtRecords(pairs, entityId)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": err.Error(),
		})
	}

	// Проверяем дубликаты по serial_number
	for _, rec := range records {
		if rec.SerialNumber != "" {
			var dupCount int
			err = db.Get(&dupCount, "SELECT COUNT(*) FROM ca_certs_ext WHERE serial_number = ?", rec.SerialNumber)
			if err == nil && dupCount > 0 {
				return c.Status(400).JSON(fiber.Map{
					"status":  "error",
					"message": fmt.Sprintf("Certificate '%s' (serial: %s) already exists", rec.CommonName, rec.SerialNumber),
				})
			}
		}
	}

	// Сохраняем в БД
	tx := db.MustBegin()
	var txCommitted bool
	defer func() {
		if !txCommitted && tx != nil {
			tx.Rollback()
		}
	}()

	for _, rec := range records {
		_, err = tx.Exec(`INSERT INTO ca_certs_ext (
			entity_ca_id, type_ca, common_name, public_key, private_key,
			cert_create_time, cert_expire_time, days_left, serial_number,
			cert_status, algorithm, key_length
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			rec.EntityCAId, rec.TypeCA, rec.CommonName, rec.PublicKey, rec.PrivateKey,
			rec.CertCreateTime, rec.CertExpireTime, rec.DaysLeft, rec.SerialNumber,
			rec.CertStatus, rec.Algorithm, rec.KeyLength)
		if err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Failed to save certificate: " + err.Error(),
			})
		}
	}

	if err = tx.Commit(); err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to commit transaction: " + err.Error(),
		})
	}
	txCommitted = true

	slog.Info("ExtCAController: external CA certificates uploaded", "entity_ca_id", entityId, "count", len(records))

	return c.Status(200).JSON(fiber.Map{
		"status":  "success",
		"message": fmt.Sprintf("Successfully uploaded %d CA certificate(s)", len(records)),
	})
}

func ExtCAListController(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("ExtCAListController: database connection error", "error", err)
	}
	defer db.Close()

	extCAList := []models.CAExtData{}
	err = db.Select(&extCAList, `SELECT e.id, e.entity_ca_id, e.type_ca, e.common_name, e.algorithm, e.key_length,
		e.cert_create_time, e.cert_expire_time, e.days_left, e.serial_number, e.cert_status
		FROM ca_certs_ext e WHERE e.cert_status IN (0, 1)`)
	if err != nil {
		slog.Error("ExtCAListController: error fetching ext CA list", "error", err)
	}

	// Форматируем даты
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

func readExtCAFormFile(fh *multipart.FileHeader) ([]byte, error) {
	f, err := fh.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
