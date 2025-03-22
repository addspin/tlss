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

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.Id == "" ||
			data.ServerId == "" ||
			data.DaysLeft == "" {

			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Отсутствуют обязательные поля ID сертификата, ID сервера, количество дней до истечения срока действия сертификата",
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
		serverID, err := strconv.Atoi(data.ServerId)
		if err != nil {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid server ID value",
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
		// Обновляем статус сертификата с учетом ID сервера и ID сертификата
		_, err = tx.Exec(`UPDATE certs SET 
			cert_status = ?, 
			data_revoke = ?
			WHERE id = ? AND server_id = ?`, certStatus, currentTime, certID, serverID)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка при отзыве сертификата: " + err.Error(),
			})
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
