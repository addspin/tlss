package controllers

import (
	"log/slog"
	"strconv"

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
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.ServerData)
		c.Bind().JSON(data)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.Hostname == "" || data.Username == "" || data.TlssSSHport == 0 || data.Path == "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}
		if data.SSHKey != "" && data.Password != "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Choose one: Password or Key. If password is selected, the Default key will be copied to the server",
			})
		}

		// Добавление сервера
		if data.Hostname != "" && data.Username != "" && data.TlssSSHport != 0 && data.Path != "" || data.SSHKey != "" || data.Password != "" {
			// Добавить ключ доступа на удленный сервер
			tlsPort := strconv.Itoa(data.TlssSSHport)
			err = crypts.AddAuthorizedKeys(db, data.Hostname, tlsPort, data.Username, data.Password, data.Path, data.SSHKey)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": err.Error(),
				})
			}
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
				dataInsert := `INSERT INTO server (hostname, port, username, cert_config_path) VALUES ($1, $2, $3, $4)`
				_, err = tx.Exec(dataInsert, data.Hostname, data.TlssSSHport, data.Username, data.Path)
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
					"message": "Server successfully added",
				})
			}
		}
	}
	if c.Method() == "GET" {
		serverList := []models.Server{}
		err := db.Select(&serverList, "SELECT id, hostname, COALESCE(cert_config_path, '') as cert_config_path, server_status FROM server WHERE cert_config_path NOT NULL")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}
		sshKeyList := []models.SSHKey{}
		err = db.Select(&sshKeyList, "SELECT name_ssh_key FROM ssh_key")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}

		data := fiber.Map{
			"Title":      "Add server",
			"serverList": &serverList,
			"sshKeyList": &sshKeyList,
		}

		// Проверяем, является ли запрос HTMX запросом
		if c.Get("HX-Request") != "" {
			err := c.Render("addServer-content", data, "")
			if err != nil {
				slog.Error("Error rendering addServer-content", "error", err)
				return err
			}
			return nil
		}

		return c.Render("add_server/addServer", data)
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// ServerListController обрабатывает запросы на получение списка серверов
func ServerListController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		serverList := []models.Server{}
		err = db.Select(&serverList, "SELECT id, hostname, COALESCE(cert_config_path, '') as cert_config_path, server_status FROM server WHERE cert_config_path NOT NULL")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}

		// Рендерим только шаблон списка серверов
		return c.Render("add_server/serverList", fiber.Map{
			"serverList": &serverList,
		})
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
