package sshControllers

import (
	"crypto/x509"
	"encoding/pem"
	"log"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func AddSSHControll(c fiber.Ctx) error {

	//---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.SSHKey)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.NameSSHKey == "" || data.Algorithm == "" || data.KeyLength == 0 {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}
		// Добавление ssh key
		if data.NameSSHKey != "" && data.Algorithm != "" && data.KeyLength != 0 {
			// Проверяем, существует ли уже ключ с таким именем
			var existingKey models.SSHKey
			err = db.Get(&existingKey, "SELECT name_ssh_key FROM ssh_key WHERE name_ssh_key = ?", data.NameSSHKey)
			if err == nil {
				return c.Status(400).JSON(fiber.Map{
					"status":  "error",
					"message": "SSH ключ с таким именем уже существует. Используйте другое имя или удалите существующий ключ.",
				})
			}

			// Если запись не существует, генерируем ключи
			privateKey, err := crypts.GeneratePrivateKey(data.KeyLength)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка генерации приватного ключа: " + err.Error(),
				})
			}

			// Кодируем приватный ключ в PEM формат
			keyPEM := pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			})

			// Генерируем публичный ключ
			publicKeyBytes, err := crypts.GeneratePublicKey(&privateKey.PublicKey)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка генерации публичного ключа: " + err.Error(),
				})
			}

			// Шифруем приватный ключ
			aes := crypts.Aes{}
			encryptedKey, err := aes.Encrypt(keyPEM, crypts.AesSecretKey.Key)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка шифрования приватного ключа: " + err.Error(),
				})
			}

			_, err = db.Exec(`INSERT INTO ssh_key (name_ssh_key, public_key, private_key, key_length, algorithm) VALUES (?, ?, ?, ?, ?)`,
				data.NameSSHKey, string(publicKeyBytes), string(encryptedKey), data.KeyLength, data.Algorithm)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при добавлении SSH ключа: " + err.Error(),
				})
			}
			return c.Status(200).JSON(fiber.Map{
				"status":  "success",
				"message": "SSH key успешно добавлен",
			})
		}
	}
	if c.Method() == "GET" {
		sshKeyList := []models.SSHKey{}
		err = db.Select(&sshKeyList, "SELECT id, name_ssh_key, algorithm, key_length FROM ssh_key")
		if err != nil {
			log.Fatal(err)
		}
		return c.Render("add_ssh/addSSHKey", fiber.Map{
			"Title":      "Add ssh key",
			"sshKeyList": &sshKeyList,
		})
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// SSHCertListController обрабатывает запросы на получение списка ssh ключей
func SSHCertListController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		sshKeyList := []models.SSHKey{}
		err = db.Select(&sshKeyList, "SELECT id, name_ssh_key, algorithm, key_length FROM ssh_key")
		if err != nil {
			log.Fatal(err)
		}

		// Рендерим только шаблон списка серверов
		return c.Render("add_ssh/sshKeyList", fiber.Map{
			"sshKeyList": &sshKeyList,
		})
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
