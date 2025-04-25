package controllers

import (
	"fmt"
	"log"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RemoveServer(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for remove server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.ServerData)

		c.Bind().JSON(data)
		log.Println("id data:", data.Id)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.Id == "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}
		tx := db.MustBegin()

		// удаляем все revoke сертификаты, принадлежащие серверу
		dataRemoveOCSP := `DELETE FROM ocsp_revoke WHERE id = ?`
		_, err = tx.Exec(dataRemoveOCSP, data.Id)
		if err != nil {
			tx.Rollback()
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка при удалении OCSP сертификатов: " + err.Error(),
			})
		}

		// удаляем сертификаты сервера
		dataRemoveCerts := `DELETE FROM certs WHERE server_id = ?`
		_, err = tx.Exec(dataRemoveCerts, data.Id)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка при удалении сертификатов сервера: " + err.Error(),
			})
		}

		// В конце удаляем сам сервер
		dataRemove := `DELETE FROM server WHERE id = ?`
		_, err = tx.Exec(dataRemove, data.Id)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка при удалении сервера: " + err.Error(),
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
	return c.Render("add_server/serverList-tpl", fiber.Map{})
}
