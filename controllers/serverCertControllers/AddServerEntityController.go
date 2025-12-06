package controllers

import (
	"log/slog"

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
		slog.Error("Fatal error", "error", err)
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
				slog.Error("Database query error", "error", err)
				return err
			}
			if t.Next() { //Если предыдущий запрос выполнился успешно, проверяется есть ли хотябы одна строка с таким именем
				// Закрываем результат запроса
				t.Close()
				// Если значение в таблице существует, то возвращаем ошибку
				tx.Rollback() // Откатываем транзакцию
				return c.Status(400).JSON(fiber.Map{
					"status":  "error",
					"message": "Server with this name already exists",
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
				"message": "Server entity successfully added",
			})
			}
		}
	}
	if c.Method() == "GET" {
		serverEntityList := []models.Server{}
		err := db.Select(&serverEntityList, "SELECT id, TRIM(hostname) as hostname, COALESCE(description, '') as description FROM server WHERE cert_config_path IS NULL OR cert_config_path = ''")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}

		data := fiber.Map{
			"Title":            "Add server entity",
			"serverEntityList": &serverEntityList,
		}

		// Проверяем, является ли запрос HTMX запросом
		if c.Get("HX-Request") != "" {
			err := c.Render("addServerEntity-content", data, "")
			if err != nil {
				slog.Error("Error rendering addServerEntity-content", "error", err)
				return err
			}
			return nil
		}

		return c.Render("add_server/addServerEntity", data)
	}
	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// EntityServerListController обрабатывает запросы на получение списка серверных сущностей
func EntityServerListController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		serverEntityList := []models.Server{}
		err := db.Select(&serverEntityList, "SELECT id, TRIM(hostname) as hostname, COALESCE(description, '') as description FROM server WHERE cert_config_path IS NULL OR cert_config_path = ''")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}

		return c.Render("add_server/entityServerList", fiber.Map{
			"serverEntityList": &serverEntityList,
		})
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
