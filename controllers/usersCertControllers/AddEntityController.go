package controllers

import (
	"fmt"
	"log"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func AddEntityController(c fiber.Ctx) error {

	//---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.EntityData)

		c.Bind().JSON(data)
		log.Println(data.EntityName, data.EntityDescription)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.EntityName == "" || data.EntityDescription == "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}

		// Проверяем есть ли в таблице значение entity_name
		tx := db.MustBegin()

		dataTest := `SELECT * FROM entity WHERE entity_name = $1`
		t, err := tx.Query(dataTest, data.EntityName)
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
				"message": "Сущность с таким именем уже существует",
			})
		} else {
			// Закрываем результат запроса
			t.Close()
			// Иначе вставляем новое значение
			dataInsert := `INSERT INTO entity (entity_name, entity_description) VALUES ($1, $2)`
			_, err = tx.Exec(dataInsert, data.EntityName, data.EntityDescription)
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
	if c.Method() == "GET" {
		entityList := []models.Entity{}
		err := db.Select(&entityList, "SELECT id, entity_name, entity_description FROM entity")
		if err != nil {
			log.Fatal(err)
		}
		log.Println("entityList", entityList)
		return c.Render("add_entity/addEntity", fiber.Map{
			"Title":      "Add entity",
			"entityList": &entityList,
		})
	}
	entityList := []models.Entity{}
	error := db.Select(&entityList, "SELECT id, entity_name, entity_description FROM entity")
	if error != nil {
		log.Fatal(err)
	}
	log.Println("entityList", entityList)
	return c.Render("add_entity/addEntity", fiber.Map{
		"Title":      "Add entity",
		"entityList": &entityList,
	})
}
