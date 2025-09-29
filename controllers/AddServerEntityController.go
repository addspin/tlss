package controllers

import (
	"log"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func AddServerEntityController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.ServerData)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.Hostname == "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}

		// Добавление сущности для серверных сертфиикатов
		if data.Hostname != "" {
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
				dataInsert := `INSERT INTO server (hostname, description) VALUES ($1, $2)`
				_, err = tx.Exec(dataInsert, data.Hostname, data.Description)
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

				serverEntityList := []models.Server{}
				err := db.Select(&serverEntityList, "SELECT id, TRIM(hostname) as hostname, COALESCE(description, '') as description FROM server WHERE cert_config_path IS NULL OR cert_config_path = ''")
				if err != nil {
					log.Fatal(err)
				}

				return c.Render("add_server/addServerEntity", fiber.Map{
					"Title":            "Add server entity",
					"serverEntityList": &serverEntityList,
				})
			}
		}
	}
	if c.Method() == "GET" {
		serverEntityList := []models.Server{}
		err := db.Select(&serverEntityList, "SELECT id, TRIM(hostname) as hostname, COALESCE(description, '') as description FROM server WHERE cert_config_path IS NULL OR cert_config_path = ''")
		if err != nil {
			log.Fatal(err)
		}

		return c.Render("add_server/addServerEntity", fiber.Map{
			"Title":            "Add server entity",
			"serverEntityList": &serverEntityList,
		})
	}
	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
