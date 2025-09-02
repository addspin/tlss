package controllers

import (
	"encoding/pem"
	"log"

	"github.com/addspin/tlss/crl"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

const (
	rootCADERcrl   = "rootcaDER.crl"
	subCADERcrl    = "subcaDER.crl"
	rootCAPEMcrl   = "rootcaPEM.crl"
	subCAPEMcrl    = "subcaPEM.crl"
	bundleCADERcrl = "bundlecaDER.crl"
	bundleCAPEMcrl = "bundlecaPEM.crl"
)

// принудительно генерирует CRL для Root CA и Sub CA
func GenerateCombinedCACRL(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to database: ", database)
	defer db.Close()

	err = crl.CombinedCRL(db)
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка генерации CRL для серверных и клиентских сертификатов подписанных Root CA и Sub CA: " + err.Error(),
		})
	}
	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "CRL для серверных и клиентских сертификатов подписанных Root CA и Sub CA успешно сгенерирован",
	})
}

// GetBudleCRL обрабатывает запрос на получение бандла DER файла CRL
func GetBundleCACRL(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to database: ", database)
	defer db.Close()
	var crlData models.CRL
	err = db.Get(&crlData, "SELECT * FROM crl WHERE type_crl = 'Bundle'")
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}

	// Декодируем все PEM блоки из бандла и склеиваем их в DER формат
	pemData := []byte(crlData.DataCRL)
	var bundleDer []byte

	// Декодируем все PEM блоки в бандле
	for {
		block, rest := pem.Decode(pemData)
		if block == nil {
			break
		}
		bundleDer = append(bundleDer, block.Bytes...)
		pemData = rest
	}

	if len(bundleDer) == 0 {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Ошибка декодирования CRL данных бандла",
		})
	}

	// Устанавливаем заголовки для CRL файла в DER формате
	c.Set("Content-Disposition", "attachment; filename="+bundleCADERcrl)
	c.Set("Content-Type", "application/pkix-crl")

	return c.Send(bundleDer)
}

func GetBundleCAPemCRL(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to database: ", database)
	defer db.Close()

	var crlData models.CRL
	err = db.Get(&crlData, "SELECT * FROM crl WHERE type_crl = 'Bundle'")
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}

	// Данные уже в правильном PEM формате (бандл с двумя отдельными блоками)
	// Устанавливаем заголовки для CRL файла
	c.Set("Content-Disposition", "attachment; filename="+bundleCAPEMcrl)
	c.Set("Content-Type", "application/x-pem-file")

	return c.Send([]byte(crlData.DataCRL))
}

// GetCRL обрабатывает запрос на получение CRL файла
func GetRootCACRL(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to database: ", database)
	defer db.Close()
	// Используем только DER CRL файл для серверных и клиентских сертификатов подписанных Sub CA
	var crlData models.CRL
	err = db.Get(&crlData, "SELECT * FROM crl WHERE type_crl = 'Root'")
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}

	// Декодируем PEM данные обратно в DER формат
	block, _ := pem.Decode([]byte(crlData.DataCRL))
	if block == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Ошибка декодирования CRL данных",
		})
	}

	// Устанавливаем заголовки для CRL файла
	c.Set("Content-Disposition", "attachment; filename="+rootCADERcrl)
	c.Set("Content-Type", "application/pkix-crl")

	// Отправляем файл
	return c.Send(block.Bytes)
}

// GetCRL обрабатывает запрос на получение CRL файла
func GetRootCAPemCRL(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to database: ", database)
	defer db.Close()
	// Используем только PEM CRL файл для серверных и клиентских сертификатов подписанных Sub CA
	var crlData models.CRL
	err = db.Get(&crlData, "SELECT * FROM crl WHERE type_crl = 'Root'")
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}

	// Преобразуем данные из базы в PEM формат
	crldb := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: []byte(crlData.DataCRL),
	})

	// Устанавливаем заголовки для CRL файла
	c.Set("Content-Disposition", "attachment; filename="+rootCAPEMcrl)
	c.Set("Content-Type", "application/x-pem-file")

	// Отправляем файл
	return c.Send(crldb)
}

// GetSubCACRL обрабатывает запрос на получение CRL файла
func GetSubCACRL(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to database: ", database)
	defer db.Close()
	// Используем только DER CRL файл для серверных и клиентских сертификатов подписанных Sub CA
	var crlData models.CRL
	err = db.Get(&crlData, "SELECT * FROM crl WHERE type_crl = 'Sub'")
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}

	// Декодируем PEM данные обратно в DER формат
	block, _ := pem.Decode([]byte(crlData.DataCRL))
	if block == nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"error": "Ошибка декодирования CRL данных",
		})
	}

	// Устанавливаем заголовки для CRL файла
	c.Set("Content-Disposition", "attachment; filename="+subCADERcrl)
	c.Set("Content-Type", "application/pkix-crl")

	// Отправляем файл
	return c.Send(block.Bytes)
}

// GetCRL обрабатывает запрос на получение PEM CRL файла
func GetSubCAPemCRL(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to database: ", database)
	defer db.Close()

	var crlData models.CRL
	err = db.Get(&crlData, "SELECT * FROM crl WHERE type_crl = 'Sub'")
	if err != nil {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}
	// Преобразуем данные из базы в PEM формат
	crldb := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: []byte(crlData.DataCRL),
	})

	// Устанавливаем заголовки для CRL файла
	c.Set("Content-Disposition", "attachment; filename="+subCAPEMcrl)
	c.Set("Content-Type", "application/x-pem-file")

	// Отправляем файл
	return c.Send(crldb)
}
