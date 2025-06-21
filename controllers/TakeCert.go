package controllers

import (
	"archive/zip"
	"bytes"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func TakeCert(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	// Только GET запрос для прямого скачивания файла
	if c.Method() != "GET" {
		return c.Status(405).JSON(fiber.Map{
			"status":  "error",
			"message": "Метод не разрешен. Используйте GET запрос.",
		})
	}

	// GET запрос для прямого скачивания файла
	serverId := c.Query("serverId")
	id := c.Query("id")

	if serverId == "" || id == "" {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Отсутствуют параметры serverId или id",
		})
	}

	// Извлекаем Sub CA из базы данных
	var subCACert string
	err = db.Get(&subCACert, "SELECT public_key FROM sub_ca_tlss WHERE id = 1")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": fmt.Sprintf("Не удалось получить промежуточный сертификат: %v", err),
		})
	}

	// Извлекаем сертификаты из базы данных
	certList := []models.CertsData{}
	err = db.Select(&certList, "SELECT domain, public_key, private_key FROM certs WHERE server_id = ? and id = ?", serverId, id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка извлечения сертификата",
		})
	}

	if len(certList) == 0 {
		return c.Status(404).JSON(fiber.Map{
			"status":  "error",
			"message": "Сертификат не найден",
		})
	}

	publicKey := certList[0].PublicKey
	privateKey := certList[0].PrivateKey
	domain := certList[0].Domain

	// Расшифровываем приватный ключ
	aes := crypts.Aes{}
	decryptedKey, err := aes.Decrypt([]byte(privateKey), crypts.AesSecretKey.Key)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка расшифровки приватного ключа",
		})
	}

	// Проверяем, что приватный ключ корректно расшифрован
	subCAKeyBlock, _ := pem.Decode(decryptedKey)
	if subCAKeyBlock == nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Не удалось декодировать PEM приватного ключа",
		})
	}

	// Создаем ZIP архив
	var buf bytes.Buffer
	zipWriter := zip.NewWriter(&buf)

	// Добавляем Sub CA сертификат
	subCAFile, err := zipWriter.Create("sub_ca.crt")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка создания архива",
		})
	}
	_, err = subCAFile.Write([]byte(subCACert))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка записи Sub CA в архив",
		})
	}

	// Добавляем публичный ключ (сертификат)
	publicKeyFile, err := zipWriter.Create(domain + ".crt")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка создания файла сертификата в архиве",
		})
	}
	_, err = publicKeyFile.Write([]byte(publicKey))
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка записи сертификата в архив",
		})
	}

	// Добавляем приватный ключ
	privateKeyFile, err := zipWriter.Create(domain + ".key")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка создания файла приватного ключа в архиве",
		})
	}
	_, err = privateKeyFile.Write(decryptedKey)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка записи приватного ключа в архив",
		})
	}

	// Закрываем ZIP writer
	err = zipWriter.Close()
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка закрытия архива",
		})
	}

	// Устанавливаем заголовки для скачивания файла
	fileName := fmt.Sprintf("certificate_%s.zip", domain)
	c.Set("Content-Type", "application/zip")
	c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
	c.Set("Content-Length", fmt.Sprintf("%d", buf.Len()))

	// Отправляем ZIP архив пользователю
	return c.Send(buf.Bytes())
}
