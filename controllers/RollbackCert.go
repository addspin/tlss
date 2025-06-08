package controllers

import (
	"fmt"
	"log"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/addspin/tlss/utils"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RollbackCert(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for remove server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.CertsData)

		c.Bind().JSON(data)
		log.Println("id data:", data.Id)
		log.Println("server_id data:", data.ServerId)
		log.Println("save_on_server data:", data.SaveOnServer)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.Id == 0 ||
			data.ServerId == 0 ||
			data.DaysLeft == 0 {

			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Отсутствуют обязательные поля ID сертификата, ID сервера, количество дней до истечения срока действия сертификата",
			})
		}
		tx := db.MustBegin()

		var certStatus int
		if data.DaysLeft <= 0 {
			certStatus = 1
		} else {
			certStatus = 0
		}

		// Получаем серийный номер и домен сертификата для удаления из OCSP
		var serialNumber, domain string
		err = db.QueryRow("SELECT serial_number, domain FROM certs WHERE id = ? AND server_id = ?", data.Id, data.ServerId).Scan(&serialNumber, &domain)
		if err != nil {
			// tx.Rollback()
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка при получении данных сертификата: " + err.Error(),
			})
		}

		currentTime := ""
		// Обновляем статус сертификата с учетом ID сервера и ID сертификата
		_, err = tx.Exec(`UPDATE certs SET 
			cert_status = ?, 
			data_revoke = ?,
			reason_revoke = ?
			WHERE id = ? AND server_id = ?`, certStatus, currentTime, "", data.Id, data.ServerId)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка при восстановлении сертификата: " + err.Error(),
			})
		}

		// Удаляем сертификат из таблицы ocsp_revoke
		_, err = tx.Exec("DELETE FROM ocsp_revoke WHERE serial_number = ?", serialNumber)
		if err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка при удалении сертификата из OCSP: " + err.Error(),
			})
		}

		log.Printf("Сертификат для домена %s (серийный номер: %s) успешно восстановлен и удален из OCSP", domain, serialNumber)

		if data.SaveOnServer {
			// Изменим имя сертифмката с wildcard именами с  *.test.ru на test.ru
			// в POST приходят именя с фронта, но в базе данных они хранятся без wildcard
			data.Domain = domain
			// Извлекаем сертификат и ключ из базы данных
			// var publicKey, privateKey string
			keyList := []models.CertsData{}
			err = db.Select(&keyList, "SELECT public_key, private_key FROM certs WHERE id = ? AND server_id = ?", data.Id, data.ServerId)
			if err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при получении сертификата и ключа из базы данных: " + err.Error(),
				})
			}

			if len(keyList) == 0 {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Сертификат не найден в базе данных",
				})
			}

			// Расшифровываем приватный ключ
			aes := crypts.Aes{}
			decryptedKey, err := aes.Decrypt([]byte(keyList[0].PrivateKey), crypts.AesSecretKey.Key)
			if err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при расшифровке приватного ключа: " + err.Error(),
				})
			}

			saveOnServer := utils.NewSaveOnServer()

			err = saveOnServer.SaveOnServer(data, db, []byte(keyList[0].PublicKey), decryptedKey)
			if err != nil {
				log.Printf("Ошибка сохранения сертификата на сервер: %v", err)
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка сохранения сертификата на сервер: " + err.Error(),
				})
			}
		}

		err = tx.Commit() // Проверяем ошибку при коммите
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка при сохранении изменений: " + err.Error(),
			})
		}

		return c.Render("revoke_certs/certRevokeList-tpl", fiber.Map{})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
