package controllers

import (
	"fmt"
	"log"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func AddServerControll(c fiber.Ctx) error {

	//---------------------------------------Database inicialization for add server
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
		log.Println(data.Hostname, data.Username, data.Password, data.TlssSSHport, data.Path)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.Hostname == "" || data.Username == "" || data.Password == "" || data.TlssSSHport == "" || data.Path == "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}
		// Добавить ключ доступа на удленный сервер
		err = crypts.AddAuthorizedKeys(data.Hostname, data.TlssSSHport, data.Username, data.Password)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": err.Error(),
			})
		} else {
			// Проверяем есть ли в таблице значение hostname
			tx := db.MustBegin()

			dataTest := `SELECT * FROM server WHERE hostname = $1`
			t, err := tx.Query(dataTest, data.Hostname)
			if err != nil {
				log.Fatal(err.Error())
			}
			if t.Next() { //Если предыдущий запрос выполнился успешно, проверяется есть ли хотябы одна строка с таким именем
				// Закрываем результат запроса
				t.Close()
				// Если значение в таблице существует, то возвращаем ошибку
				tx.Rollback() // Откатываем транзакцию
				return c.Status(400).JSON(fiber.Map{
					"status":  "error",
					"message": "Сервер с таким именем уже существует",
				})
			} else {
				// Закрываем результат запроса
				t.Close()
				// Иначе вставляем новое значение
				dataInsert := `INSERT INTO server (hostname, port, username, cert_config_path) VALUES ($1, $2, $3, $4)`
				_, err = tx.Exec(dataInsert, data.Hostname, data.TlssSSHport, data.Username, data.Path)
				if err != nil {
					tx.Rollback() // Откатываем транзакцию при ошибке
					return c.Status(500).JSON(fiber.Map{
						"status":  "error",
						"message": "Ошибка при добавлении данных в базу данных: " + err.Error(),
					})
				}
				err = tx.Commit() // Проверяем ошибку при коммите
				if err != nil {
					return c.Status(500).JSON(fiber.Map{
						"status":  "error",
						"message": "Ошибка при сохранении данных: " + err.Error(),
					})
				}
			}
		}
	}
	if c.Method() == "GET" {
		serverList := []models.Server{}
		err := db.Select(&serverList, "SELECT id, hostname, cert_config_path, server_status FROM server")
		if err != nil {
			log.Fatal(err)
		}
		log.Println("serverList", serverList)
		return c.Render("add_server/addServer", fiber.Map{
			"Title":      "Add server",
			"serverList": &serverList,
		})
	}
	serverList := []models.Server{}
	error := db.Select(&serverList, "SELECT id, hostname, cert_config_path, server_status FROM server")
	if error != nil {
		log.Fatal(err)
	}
	log.Println("serverList", serverList)
	return c.Render("add_server/addServer", fiber.Map{
		"Title":      "Add server",
		"serverList": &serverList,
	})
}
