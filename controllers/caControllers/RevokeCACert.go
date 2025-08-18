package caControllers

import (
	"fmt"
	"log"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RevokeCACert(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for remove server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.CAData)

		c.Bind().JSON(data)
		log.Println("type_ca data:", data.TypeCA)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.TypeCA == "" ||
			data.ReasonRevoke == "" {

			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Отсутствуют обязательные поля ID сертификата или ID сервера",
			})
		}
		tx := db.MustBegin()

		currentTime := time.Now().Format(time.RFC3339)
		reasonRevoke := data.ReasonRevoke
		typeCA := data.TypeCA
		revokeStatus := 2  // 2 - revoked
		validStatus := 0   // 0 - valid
		expiredStatus := 1 // 1 - expired

		// Перед вставкой нового сертификата помечаем текущий активный Root CA и Sub CA как отозванный
		if typeCA == "Root" {
			_, err := tx.Exec(`UPDATE ca_certs SET
				cert_status = ?,
				data_revoke = ?,
				reason_revoke = ?
				WHERE cert_status = ?`, revokeStatus, currentTime, reasonRevoke, validStatus)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "root ca: Ошибка при обновлении метки об отзыве сертификатов: " + err.Error(),
				})
			}

			// Отзываем все сертификаты подписанные CA
			// Серверные сертификаты
			_, err = tx.Exec(`UPDATE certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE cert_status IN (?, ?)`, revokeStatus, currentTime, reasonRevoke, expiredStatus, validStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при отзыве серверных сертификатов: " + err.Error(),
				})
			}

			// Клиентские сертификаты
			_, err = tx.Exec(`UPDATE user_certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE cert_status IN (?, ?)`, revokeStatus, currentTime, reasonRevoke, expiredStatus, validStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при отзыве клиентских сертификатов: " + err.Error(),
				})
			}

			// Пересоздаем Root CA и Sub CA
			crypts.GenerateRSARootCA(data, db)
		}

		if typeCA == "Sub" {
			// Перед вставкой нового сертификата помечаем текущий активный Sub CA как отозванный
			_, err = tx.Exec(`UPDATE ca_certs SET
			cert_status = ?,
			data_revoke = ?,
			reason_revoke = ?
			WHERE type_ca = ? AND cert_status = ?`, revokeStatus, currentTime, reasonRevoke, typeCA, validStatus)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "sub ca: Ошибка при обновлении метки об отзыве сертификатов: " + err.Error(),
				})
			}

			// Отзываем все сертификаты подписанные CA
			// Серверные сертификаты
			_, err = tx.Exec(`UPDATE certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE cert_status IN (?, ?)`, revokeStatus, currentTime, reasonRevoke, expiredStatus, validStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при отзыве серверных сертификатов: " + err.Error(),
				})
			}

			// Клиентские сертификаты
			_, err = tx.Exec(`UPDATE user_certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE cert_status IN (?, ?)`, revokeStatus, currentTime, reasonRevoke, expiredStatus, validStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при отзыве клиентских сертификатов: " + err.Error(),
				})
			}

			// Пересоздаем Sub CA
			crypts.GenerateRSASubCA(data, db)
		}

		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "sub ca: Ошибка при отзыве сертификата: " + err.Error(),
			})
		}
		err = tx.Commit() // Проверяем ошибку при коммите
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "root/sub ca: Ошибка при сохранении изменений: " + err.Error(),
			})
		}
	}
	return c.Render("ca/certCAList-tpl", fiber.Map{})
}
