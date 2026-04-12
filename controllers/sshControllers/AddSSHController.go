package sshControllers

import (
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"io"
	"log/slog"
	"mime/multipart"
	"strings"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

func AddSSHControll(c fiber.Ctx) error {

	//---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "POST" {
		contentType := c.Get("Content-Type")

		// Режим загрузки файла (multipart)
		if strings.HasPrefix(contentType, "multipart/form-data") {
			return handleSSHKeyUpload(c, db)
		}

		// Режим генерации (JSON)
		return handleSSHKeyGenerate(c, db)
	}
	if c.Method() == "GET" {
		sshKeyList := []models.SSHKey{}
		err = db.Select(&sshKeyList, "SELECT id, name_ssh_key, algorithm, key_length FROM ssh_key")
		if err != nil {
			slog.Error("Fatal error", "error", err)
		}

		data := fiber.Map{
			"Title":      "Add ssh key",
			"sshKeyList": &sshKeyList,
		}

		// Проверяем, является ли запрос HTMX запросом
		if c.Get("HX-Request") != "" {
			// Возвращаем только контент без layout
			err := c.Render("addSSHKey-content", data, "")
			if err != nil {
				slog.Error("Error rendering addSSHKey-content", "error", err)
				return err
			}
			return nil
		}

		return c.Render("add_ssh/addSSHKey", data)
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// handleSSHKeyGenerate обрабатывает генерацию SSH ключа из формы (JSON)
func handleSSHKeyGenerate(c fiber.Ctx, db *sqlx.DB) error {
	data := new(models.SSHKey)

	err := c.Bind().JSON(data)
	if err != nil {
		return c.Status(400).JSON(
			fiber.Map{"status": "error",
				"message": "Cannot parse JSON!",
				"data":    err},
		)
	}
	if data.NameSSHKey == "" || data.Algorithm == "" {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Missing required fields: NameSSHKey and Algorithm are required",
		})
	}

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

	var existingKey models.SSHKey
	err = db.Get(&existingKey, "SELECT name_ssh_key FROM ssh_key WHERE name_ssh_key = ?", data.NameSSHKey)
	if err == nil {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "SSH key with this name already exists. Use a different name or delete the existing key.",
		})
	}

	var keyPEM []byte
	var publicKeyBytes []byte

	switch data.Algorithm {
	case "ED25519":
		publicKey, privateKey, err := crypts.GenerateED25519SSHKeyPair()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error generating ED25519 key pair: " + err.Error(),
			})
		}

		keyPEM, err = crypts.EncodeED25519PrivateKeyToPEMForSSH(privateKey)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error encoding ED25519 private key: " + err.Error(),
			})
		}

		publicKeyBytes, err = crypts.GenerateED25519PublicKeyForSSH(publicKey)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error generating ED25519 public key: " + err.Error(),
			})
		}

		data.KeyLength = 256

	case "RSA":
		privateKey, err := crypts.GeneratePrivateKeyForSSH(data.KeyLength)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error generating RSA private key: " + err.Error(),
			})
		}

		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})

		publicKeyBytes, err = crypts.GeneratePublicKeyForSSH(&privateKey.PublicKey)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error generating RSA public key: " + err.Error(),
			})
		}

	default:
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Internal error: unknown algorithm",
		})
	}

	aes := crypts.Aes{}
	encryptedKey, err := aes.Encrypt(keyPEM, crypts.AesSecretKey.Key)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Error encrypting private key: " + err.Error(),
		})
	}

	_, err = db.Exec(`INSERT INTO ssh_key (name_ssh_key, public_key, private_key, key_length, algorithm) VALUES (?, ?, ?, ?, ?)`,
		data.NameSSHKey, string(publicKeyBytes), string(encryptedKey), data.KeyLength, data.Algorithm)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Error adding SSH key: " + err.Error(),
		})
	}

	return c.Status(200).JSON(fiber.Map{
		"status":  "success",
		"message": "SSH key successfully added",
		"data": fiber.Map{
			"name":      data.NameSSHKey,
			"algorithm": data.Algorithm,
			"keyLength": data.KeyLength,
		},
	})
}

// Обрабатывает загрузку пары SSH ключей Поддерживаемые алгоритмы: RSA, ED25519
func handleSSHKeyUpload(c fiber.Ctx, db *sqlx.DB) error {
	name := c.FormValue("nameSSHKey")
	if name == "" {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Name is required",
		})
	}

	// Проверяем, существует ли уже ключ с таким именем
	var existingKey models.SSHKey
	err := db.Get(&existingKey, "SELECT name_ssh_key FROM ssh_key WHERE name_ssh_key = ?", name)
	if err == nil {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "SSH key with this name already exists. Use a different name or delete the existing key.",
		})
	}

	// Читаем оба файла
	file1, err := c.FormFile("ssh_file_1")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Two files are required: private key and public key",
		})
	}
	file2, err := c.FormFile("ssh_file_2")
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Two files are required: private key and public key",
		})
	}

	bytes1, err := readFormFile(file1)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to read file: " + file1.Filename,
		})
	}
	bytes2, err := readFormFile(file2)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Failed to read file: " + file2.Filename,
		})
	}

	// Определяем какой файл приватный, а какой публичный
	var privBytes, pubBytes []byte
	var rawKey interface{}

	rawKey, err = ssh.ParseRawPrivateKey(bytes1)
	if err == nil {
		privBytes = bytes1
		pubBytes = bytes2
	} else {
		rawKey, err = ssh.ParseRawPrivateKey(bytes2)
		if err == nil {
			privBytes = bytes2
			pubBytes = bytes1
		} else {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Could not find a valid private key in uploaded files",
			})
		}
	}

	// Определяем алгоритм и длину ключа
	var algorithm string
	var keyLength int

	switch key := rawKey.(type) {
	case *rsa.PrivateKey:
		algorithm = "RSA"
		keyLength = key.N.BitLen()
	case *ed25519.PrivateKey:
		algorithm = "ED25519"
		keyLength = 256
	default:
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Unsupported key type. Only RSA and ED25519 are supported",
		})
	}

	// Валидируем публичный ключ
	_, _, _, _, err = ssh.ParseAuthorizedKey(pubBytes)
	if err != nil {
		return c.Status(400).JSON(fiber.Map{
			"status":  "error",
			"message": "Could not find a valid public key in uploaded files",
		})
	}

	// Шифруем приватный ключ
	aes := crypts.Aes{}
	encryptedKey, err := aes.Encrypt(privBytes, crypts.AesSecretKey.Key)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Error encrypting private key: " + err.Error(),
		})
	}

	// Сохраняем в базу данных
	_, err = db.Exec(`INSERT INTO ssh_key (name_ssh_key, public_key, private_key, key_length, algorithm) VALUES (?, ?, ?, ?, ?)`,
		name, strings.TrimSpace(string(pubBytes)), string(encryptedKey), keyLength, algorithm)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Error adding SSH key: " + err.Error(),
		})
	}

	return c.Status(200).JSON(fiber.Map{
		"status":  "success",
		"message": "SSH key pair successfully uploaded",
		"data": fiber.Map{
			"name":      name,
			"algorithm": algorithm,
			"keyLength": keyLength,
		},
	})
}

// readFormFile читает содержимое загруженного файла
func readFormFile(fh *multipart.FileHeader) ([]byte, error) {
	f, err := fh.Open()
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// SSHCertListController обрабатывает запросы на получение списка ssh ключей
func SSHCertListController(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	defer db.Close()

	if c.Method() == "GET" {
		sshKeyList := []models.SSHKey{}
		err = db.Select(&sshKeyList, "SELECT id, name_ssh_key, algorithm, key_length FROM ssh_key")
		if err != nil {
			slog.Error("Fatal error", "error", err)
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
