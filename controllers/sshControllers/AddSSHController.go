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
		// Базовая валидация
		if data.NameSSHKey == "" || data.Algorithm == "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields: NameSSHKey and Algorithm are required",
			})
		}

		// Валидация специфичных параметров для каждого алгоритма
		switch data.Algorithm {
		case "ED25519":
			if data.KeyLength != 256 {
				return c.Status(400).JSON(fiber.Map{
					"status":  "error",
					"message": "Missing required field: KeyLength is required 256",
				})
			}
		case "RSA":
			if data.KeyLength == 0 {
				return c.Status(400).JSON(fiber.Map{
					"status":  "error",
					"message": "Missing required field: KeyLength is required for RSA algorithm",
				})
			}
		case "ECDSA":
			// Зарезервировано для будущей реализации ECDSA
			return c.Status(501).JSON(fiber.Map{
				"status":  "error",
				"message": "ECDSA algorithm is not implemented yet",
			})
		default:
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Unsupported algorithm: " + data.Algorithm + ". Supported algorithms: RSA, ED25519",
			})
		}

		// Проверяем, существует ли уже ключ с таким именем
		var existingKey models.SSHKey
		err = db.Get(&existingKey, "SELECT name_ssh_key FROM ssh_key WHERE name_ssh_key = ?", data.NameSSHKey)
		if err == nil {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "SSH ключ с таким именем уже существует. Используйте другое имя или удалите существующий ключ.",
			})
		}

		var keyPEM []byte
		var publicKeyBytes []byte

		// Генерируем ключи в зависимости от алгоритма
		switch data.Algorithm {
		case "ED25519":
			// Генерация ED25519 ключей
			publicKey, privateKey, err := crypts.GenerateED25519SSHKeyPair()
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка генерации ED25519 ключевой пары: " + err.Error(),
				})
			}

			// Кодируем приватный ключ в PEM формат (PKCS8)
			keyPEM, err = crypts.EncodeED25519PrivateKeyToPEMForSSH(privateKey)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка кодирования приватного ключа ED25519: " + err.Error(),
				})
			}

			// Генерируем публичный ключ в SSH формате
			publicKeyBytes, err = crypts.GenerateED25519PublicKeyForSSH(publicKey)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка генерации публичного ключа ED25519: " + err.Error(),
				})
			}

			// ED25519 всегда использует 256-битные ключи
			data.KeyLength = 256

		case "RSA":
			// Генерация RSA ключей
			privateKey, err := crypts.GeneratePrivateKeyForSSH(data.KeyLength)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка генерации приватного ключа RSA: " + err.Error(),
				})
			}

			// Кодируем приватный ключ в PEM формат (PKCS1)
			keyPEM = pem.EncodeToMemory(&pem.Block{
				Type:  "RSA PRIVATE KEY",
				Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
			})

			// Генерируем публичный ключ
			publicKeyBytes, err = crypts.GeneratePublicKeyForSSH(&privateKey.PublicKey)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка генерации публичного ключа RSA: " + err.Error(),
				})
			}

		default:
			// Этот случай не должен произойти из-за валидации выше, но для безопасности
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Internal error: unknown algorithm",
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

		// Сохраняем в базу данных
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
			"data": fiber.Map{
				"name":      data.NameSSHKey,
				"algorithm": data.Algorithm,
				"keyLength": data.KeyLength,
			},
		})
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

		return c.Render("add_ssh/sshKeyList", fiber.Map{
			"sshKeyList": &sshKeyList,
		})
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}
