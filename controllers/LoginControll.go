package controllers

import (
	"fmt"
	"log"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/middleware"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

// Глобальная переменная для отслеживания статуса инициализации
// var SystemInitialized bool = false

func LoginControll(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "GET" {
		return c.Render("login/login", fiber.Map{
			"Title": "Login",
		})

	}

	if c.Method() == "POST" {
		data := new(models.Users)

		c.Bind().JSON(data)
		log.Println(data.Username, data.Password)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.Username == "" || data.Password == "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}
		// Проверяем пользователя
		var userExists bool
		err = db.Get(&userExists, "SELECT EXISTS (SELECT 1 FROM users WHERE username = ?)", data.Username)
		if err != nil {
			log.Println(err)
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Database error",
			})
		}

		if !userExists {
			return c.Status(401).JSON(fiber.Map{
				"status":  "error",
				"message": "Invalid username or password",
			})
		}

		//проверяем пароль, расшифрует ключ или нет
		aes := crypts.Aes{}
		var keyData []models.Key
		// pwd := []byte(data.Password)
		p := crypts.PWD{}
		password := []byte(data.Password)
		salt := crypts.PWDKey.GlobalSalt
		pwd := p.CreatePWDKeyFromUserInput(password, salt)
		db.Select(&keyData, "SELECT key_data FROM secret_key WHERE id = 1")
		for _, keyData := range keyData {
			decryptKey, err := aes.Decrypt([]byte(keyData.Key), pwd)
			if err != nil {
				return c.Status(401).JSON(fiber.Map{
					"status":  "error",
					"message": "Invalid username or password",
				})
			}
			//записываем расшифрованный ключ в переменную
			crypts.AesSecretKey.Key = decryptKey
		}

		// Create session to authenticate user
		sess, err := middleware.Store.Get(c)
		if err != nil {
			log.Println("Session error:", err)
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Session error",
			})
		}
		sess.Set("authenticated", true)
		sess.Set("username", data.Username)
		if err := sess.Save(); err != nil {
			log.Println("Session save error:", err)
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Session save error",
			})
		}

		// Redirect to the add_server route
		c.Set("HX-Redirect", "/add_server")
		return c.Status(fiber.StatusOK).JSON(fiber.Map{
			"status":   "success",
			"redirect": "/add_server",
		})
	}
	return nil
}
