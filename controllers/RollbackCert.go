package controllers

import (
	"log"

	"github.com/addspin/tlss/crl"
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

	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.CertsData)

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

		if data.SaveOnServer {
			var serverInfo models.Server
			err = db.Get(&serverInfo, "SELECT COALESCE(cert_config_path, '') as cert_config_path FROM server WHERE id = ?", data.ServerId)
			if err != nil {
				tx.Rollback()
				log.Println("RollbackCert: GetServerInfo: Ошибка при получении cert_config_path из базы данных:" + err.Error())
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при извлечении из базы данных, см. лог:" + err.Error(),
				})
			}
			if serverInfo.CertConfigPath == "" {
				tx.Rollback()
				log.Println("RollbackCert: CheckSaveOnServer: Объект не является сервером для сохранения сертификата")
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Выбран Save on server, но объект не является сервером, сохранить сертификат невозможно",
				})
			}
			// Изменим имя сертифмката с wildcard именами с  *.test.ru на test.ru
			// в POST приходят именя с фронта, но в базе данных они хранятся без wildcard

			var domain string
			err = tx.Get(&domain, "SELECT domain FROM certs WHERE id = ? AND server_id = ?", data.Id, data.ServerId)
			if err != nil {
				tx.Rollback()
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при получении домена из базы данных: " + err.Error(),
				})
			}
			data.Domain = domain
			// Извлекаем сертификат и ключ из базы данных
			// var publicKey, privateKey string
			keyList := []models.CertsData{}
			err = tx.Select(&keyList, "SELECT public_key, private_key FROM certs WHERE id = ? AND server_id = ?", data.Id, data.ServerId)
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

			crl.CombinedCRL(db)

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

		return c.Status(200).JSON(fiber.Map{
			"status": "success",
			"domain": data.Domain,
		})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
