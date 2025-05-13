package controllers

import (
	"fmt"
	"log"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RevokeUserCert(c fiber.Ctx) error {
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
			data.ReasonRevoke == "" {

			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Отсутствуют обязательные поля ID сертификата или ID сущности",
			})
		}
		tx := db.MustBegin()

		// Выносим значения из запроса
		currentTime := time.Now().Format(time.RFC3339)
		reasonRevoke := data.ReasonRevoke
		certID := data.Id
		entityID := data.EntityId
		certStatus := 2

		// Обновляем статус сертификата с учетом ID сервера и ID сертификата
		_, err = tx.Exec(`UPDATE user_certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE id = ? AND entity_id = ?`, certStatus, currentTime, reasonRevoke, certID, entityID)
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
	}
	return c.Render("add_user_certs/certUserList-tpl", fiber.Map{})
}
