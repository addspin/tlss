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
				// Если значение в таблице существует, то обновляем его
				aes := &crypts.Aes{}
				cryptPath, err := aes.Encrypt([]byte(data.Path), []byte(aes.Key))
				if err != nil {
					log.Fatal(err.Error())
				}
				// Переделать!!!! Для обновления всех значений
				dataInsert := `UPDATE server SET cert_config_path = ? WHERE hostname = ?`
				_, err = tx.Exec(dataInsert, cryptPath, data.Hostname)
				if err != nil {
					log.Fatal(err.Error())
				}
				tx.Commit()

			} else {
				// Иначе вставляем новое значение
				dataInsert := `INSERT INTO server (hostname, port, cert_config_path) VALUES ($1, $2, $3)`
				_, err = tx.Exec(dataInsert, data.Hostname, data.TlssSSHport, data.Path)
				if err != nil {
					log.Fatal(err.Error())
				}
				tx.Commit()
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
