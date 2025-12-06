package caControllers

import (
	"log/slog"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func AddEntityCAController(c fiber.Ctx) error {

	//---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}

	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.EntityCAData)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.EntityCAName == "" || data.EntityCADescription == "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}

		// Проверяем есть ли в таблице значение entity_name
		tx := db.MustBegin()

		dataTest := `SELECT * FROM entity_ca WHERE entity_ca_name = $1`
		t, err := tx.Query(dataTest, data.EntityCAName)
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
				"message": "Entity CA with this name already exists",
			})
		} else {
			// Закрываем результат запроса
			t.Close()
			// Иначе вставляем новое значение
			dataInsert := `INSERT INTO entity_ca (entity_ca_name, entity_ca_description) VALUES ($1, $2)`
			_, err = tx.Exec(dataInsert, data.EntityCAName, data.EntityCADescription)
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

			return c.Status(200).JSON(fiber.Map{
				"status":  "success",
				"message": "Entity CA successfully added",
			})
		}
	}
	if c.Method() == "GET" {
		entityCAList := []models.EntityCAData{}
		err := db.Select(&entityCAList, "SELECT id, TRIM(entity_ca_name) as entity_ca_name, TRIM(entity_ca_description) as entity_ca_description FROM entity_ca")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}
		slog.Info("Entity CA list retrieved", "count", len(entityCAList))

		data := fiber.Map{
			"Title":        "Add CA entities",
			"entityCAList": &entityCAList,
		}

		// Проверяем, является ли запрос HTMX запросом
		if c.Get("HX-Request") != "" {
			err := c.Render("addEntityCA-content", data, "")
			if err != nil {
				slog.Error("Error rendering addEntityCA-content", "error", err)
				return err
			}
			return nil
		}

		return c.Render("ca/addEntityCA", data)
	}
	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// EntityListController обрабатывает запросы на получение списка сущностей
func EntityCAListController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		entityCAList := []models.EntityCAData{}
		err := db.Select(&entityCAList, "SELECT id, TRIM(entity_ca_name) as entity_ca_name, TRIM(entity_ca_description) as entity_ca_description FROM entity_ca")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}

		return c.Render("ca/entityCAList", fiber.Map{
			"entityCAList": &entityCAList,
		})
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
