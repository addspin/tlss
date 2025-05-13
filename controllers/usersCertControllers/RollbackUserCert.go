package controllers

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RollbackUserCert(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for remove server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.UserCertsData)

		c.Bind().JSON(data)
		log.Println("id data:", data.Id)
		log.Println("entity_id data:", data.EntityId)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.Id == "" ||
			data.EntityId == "" ||
			data.DaysLeft == "" {

			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Отсутствуют обязательные поля ID сертификата, ID сущности, количество дней до истечения срока действия сертификата",
			})
		}
		tx := db.MustBegin()
		// Выносим значения из запроса
		currentTime := ""
		certID, err := strconv.Atoi(data.Id)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid cert ID value",
			})
		}
		entityID, err := strconv.Atoi(data.EntityId)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid entity ID value",
			})
		}

		daysLeftTest, err := strconv.Atoi(data.DaysLeft)
		data.DaysLeft = strings.TrimSpace(data.DaysLeft)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid days left value",
			})
		}
		var certStatus int
		if daysLeftTest <= 0 {
			certStatus = 1
		} else {
			certStatus = 0
		}

		// Получаем серийный номер и домен сертификата для удаления из user OCSP
		var serialNumber, commonName string
		err = db.QueryRow("SELECT serial_number, common_name FROM user_certs WHERE id = ? AND entity_id = ?", certID, entityID).Scan(&serialNumber, &commonName)
		if err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка при получении данных сертификата: " + err.Error(),
			})
		}

		// Обновляем статус сертификата с учетом ID сервера и ID сертификата
		_, err = tx.Exec(`UPDATE user_certs SET 
			cert_status = ?, 
			data_revoke = ?,
			reason_revoke = ?
			WHERE id = ? AND entity_id = ?`, certStatus, currentTime, "", certID, entityID)
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
				"message": "Ошибка при удалении сертификата из user OCSP: " + err.Error(),
			})
		}

		log.Printf("Сертификат для домена %s (серийный номер: %s) успешно восстановлен и удален из user OCSP", commonName, serialNumber)

		err = tx.Commit() // Проверяем ошибку при коммите
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка при сохранении изменений: " + err.Error(),
			})
		}

		return c.Render("user_revoke_certs/certUserRevokeList-tpl", fiber.Map{})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
