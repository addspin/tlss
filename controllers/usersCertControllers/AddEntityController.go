package controllers

import (
	"log/slog"

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
		slog.Error("Fatal error", "error", err)
	}

	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.EntityData)

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
			slog.Error("Fatal error", "error", err)
			return err
		}
		if t.Next() { //Если предыдущий запрос выполнился успешно, проверяется есть ли хотябы одна строка с таким именем
			// Закрываем результат запроса
			t.Close()
			// Если значение в таблице существует, то возвращаем ошибку
			tx.Rollback() // Откатываем транзакцию
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Entity with this name already exists",
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
					"message": "Error adding data to database: " + err.Error(),
				})
			}
			err = tx.Commit() // Проверяем ошибку при коммите
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Error saving data: " + err.Error(),
				})
			}
			entityList := []models.EntityData{}
			error := db.Select(&entityList, "SELECT id, TRIM(entity_name) as entity_name, TRIM(entity_description) as entity_description FROM entity")
			if error != nil {
				slog.Error("Fatal error", "error", err)
			}
			slog.Info("Entity list retrieved", "count", len(entityList))
			return c.Render("add_entity/addEntity", fiber.Map{
				"Title":      "Add entity",
				"entityList": &entityList,
			})
		}
	}
	if c.Method() == "GET" {
		entityList := []models.EntityData{}
		err := db.Select(&entityList, "SELECT id, TRIM(entity_name) as entity_name, TRIM(entity_description) as entity_description FROM entity")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}
		slog.Info("Entity list retrieved", "count", len(entityList))
		return c.Render("add_entity/addEntity", fiber.Map{
			"Title":      "Add entity",
			"entityList": &entityList,
		})
	}
	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
