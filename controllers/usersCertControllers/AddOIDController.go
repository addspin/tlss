package controllers

import (
	"log/slog"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func AddOIDController(c fiber.Ctx) error {

	//---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}

	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.OIDData)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.OIDName == "" || data.OIDDescription == "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}

		// Проверяем есть ли в таблице значение oid_name
		tx := db.MustBegin()

		dataTest := `SELECT * FROM oid WHERE oid_name = $1`
		t, err := tx.Query(dataTest, data.OIDName)
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
				"message": "Entity with this name already exists",
			})
		} else {
			// Закрываем результат запроса
			t.Close()
			// Иначе вставляем новое значение
			dataInsert := `INSERT INTO oid (oid_name, oid_description) VALUES ($1, $2)`
			_, err = tx.Exec(dataInsert, data.OIDName, data.OIDDescription)
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
			oidList := []models.OIDData{}
			error := db.Select(&oidList, "SELECT id, TRIM(oid_name) as oid_name, TRIM(oid_description) as oid_description FROM oid")
			if error != nil {
				slog.Error("Fatal error", "error", err)
			}

			return c.Render("add_oid/addOID", fiber.Map{
				"Title":   "Add OID",
				"oidList": &oidList,
			})
		}
	}
	if c.Method() == "GET" {
		oidList := []models.OIDData{}
		err := db.Select(&oidList, "SELECT id, TRIM(oid_name) as oid_name, TRIM(oid_description) as oid_description FROM oid")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}

		return c.Render("add_oid/addOID", fiber.Map{
			"Title":   "Add OID",
			"oidList": &oidList,
		})
	}
	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
