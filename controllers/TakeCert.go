package controllers

import (
	"archive/zip"
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
	"software.sslmate.com/src/go-pkcs12"
)

const (
	rootCAFileName = "root_ca_tlss.pem"
	subCAFileName  = "sub_ca_tlss.pem"
)

func TakeCert(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	if c.Method() != "GET" {
		return c.Status(405).JSON(fiber.Map{
			"status":  "error",
			"message": "Метод не разрешен. Используйте GET запрос.",
		})
	}

	// GET запрос для прямого скачивания файла
	serverId := c.Query("serverId")
	entityId := c.Query("entityId")
	id := c.Query("id")
	format := c.Query("format")
	typeCA := c.Query("typeCA")
	nameSSHKey := c.Query("NameSSHKey")

	// Обработка SSH ключей
	if nameSSHKey != "" && format == "zip" {
		var sshKey models.SSHKey
		err = db.Get(&sshKey, "SELECT name_ssh_key, public_key, private_key FROM ssh_key WHERE name_ssh_key = ?", nameSSHKey)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": fmt.Sprintf("Не удалось получить SSH ключ: %v", err),
			})
		}

		// Расшифровываем приватный ключ SSH
		aes := crypts.Aes{}
		decryptedPrivateKey, err := aes.Decrypt([]byte(sshKey.PrivateKey), crypts.AesSecretKey.Key)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": fmt.Sprintf("Ошибка расшифровки приватного SSH ключа: %v", err),
			})
		}

		// Создаем ZIP архив
		var buf bytes.Buffer
		zipWriter := zip.NewWriter(&buf)

		// Добавляем публичный ключ
		publicKeyFile, err := zipWriter.Create(sshKey.NameSSHKey + ".pub")
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка создания файла публичного ключа в архиве",
			})
		}
		_, err = publicKeyFile.Write([]byte(sshKey.PublicKey))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка записи публичного ключа в архив",
			})
		}

		// Добавляем приватный ключ
		privateKeyFile, err := zipWriter.Create(sshKey.NameSSHKey)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка создания файла приватного ключа в архиве",
			})
		}
		_, err = privateKeyFile.Write(decryptedPrivateKey)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка записи приватного ключа в архив",
			})
		}

		// Закрываем ZIP writer
		if err = zipWriter.Close(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка закрытия архива",
			})
		}

		// Устанавливаем заголовки для скачивания файла
		c.Set("Content-Type", "application/zip")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=ssh_key_%s.zip", sshKey.NameSSHKey))
		c.Set("Content-Length", fmt.Sprintf("%d", buf.Len()))

		// Отправляем ZIP архив пользователю
		return c.Send(buf.Bytes())
	}

	// Извлекаем Sub CA из базы данных
	var subCACert string
	err = db.Get(&subCACert, "SELECT public_key FROM ca_certs WHERE type_ca = 'Sub' AND cert_status = 0")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": fmt.Sprintf("Не удалось получить промежуточный сертификат: %v", err),
		})
	}

	// Извлекаем Root CA сертификат из базы данных
	var rootCACert string
	err = db.Get(&rootCACert, "SELECT public_key FROM ca_certs WHERE type_ca = 'Root' AND cert_status = 0")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": fmt.Sprintf("Не удалось получить корневой сертификат: %v", err),
		})
	}

	// Извелкаем првиатный ключ Sub CA
	var subCAKey string
	err = db.Get(&subCAKey, "SELECT private_key FROM ca_certs WHERE type_ca = 'Sub' AND cert_status = 0")
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": fmt.Sprintf("Не удалось получить приватный ключ Sub CA: %v", err),
		})
	}
	aes := crypts.Aes{}
	// Расшифровываем приватный ключ Sub CA
	decryptedSubCAKey, err := aes.Decrypt([]byte(subCAKey), crypts.AesSecretKey.Key)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка расшифровки приватного ключа Sub CA",
		})
	}
	subCAKeyBlock, _ := pem.Decode(decryptedSubCAKey)
	if subCAKeyBlock == nil {
		return c.Status(500).JSON(fiber.Map{
			"status":  "error",
			"message": "Не удалось декодировать PEM приватного ключа Sub CA",
		})
	}

	if format == "zip" && typeCA == "Root" {
		// Создаем ZIP архив
		var buf bytes.Buffer
		zipWriter := zip.NewWriter(&buf)

		// Добавляем Root CA сертификат
		rootCAFile, err := zipWriter.Create(rootCAFileName)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка создания архива",
			})
		}
		_, err = rootCAFile.Write([]byte(rootCACert))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка записи Root CA в архив",
			})
		}
		if err = zipWriter.Close(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка закрытия архива",
			})
		}
		c.Set("Content-Type", "application/zip")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", "root_ca_tlss.zip"))
		c.Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
		return c.Send(buf.Bytes())
	}

	if format == "zip" && typeCA == "Sub" {
		// Создаем ZIP архив
		var buf bytes.Buffer
		zipWriter := zip.NewWriter(&buf)

		// Добавляем Root CA сертификат
		subCAFile, err := zipWriter.Create(subCAFileName)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка создания архива",
			})
		}
		_, err = subCAFile.Write([]byte(subCACert))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка записи Sub CA в архив",
			})
		}
		if err = zipWriter.Close(); err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка закрытия архива",
			})
		}
		c.Set("Content-Type", "application/zip")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", "sub_ca_tlss.zip"))
		c.Set("Content-Length", fmt.Sprintf("%d", buf.Len()))
		return c.Send(buf.Bytes())
	}

	// Объявляем certList до условных блоков
	var certList []models.CertsData
	var publicKey *string
	var privateKey *string
	var domain *string
	var commonName *string

	// получение сертификата для сервера
	if serverId != "" {
		// Извлекаем сертификаты из базы данных (учитывайте что public_key уже содержат поля (Subject, SAN, Issuer, Extensions и т.д.)
		err = db.Select(&certList, "SELECT domain, public_key, private_key FROM certs WHERE server_id = ? and id = ?", serverId, id)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка извлечения сертификата из таблицы certs",
			})
		}
		publicKey = &certList[0].PublicKey
		privateKey = &certList[0].PrivateKey
		domain = &certList[0].Domain
	}

	// получение сертификата для пользователя (учитывайте что public_key уже содержат поля (Subject, SAN, Issuer, Extensions и т.д.)
	if entityId != "" {
		err = db.Select(&certList, "SELECT common_name, public_key, private_key FROM user_certs WHERE entity_id = ? and id = ?", entityId, id)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка извлечения сертификата из таблицы user_certs",
			})
		}
		commonName = &certList[0].CommonName
		publicKey = &certList[0].PublicKey
		privateKey = &certList[0].PrivateKey
	}

	// Расшифровываем приватный ключ сертификатов
	var decryptedKey []byte
	if privateKey != nil {
		decryptedKey, err = aes.Decrypt([]byte(*privateKey), crypts.AesSecretKey.Key)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка расшифровки приватного ключа",
			})
		}

		// Проверяем, что приватный ключ корректно расшифрован
		subCAKeyBlock, _ = pem.Decode(decryptedKey)
		if subCAKeyBlock == nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Не удалось декодировать PEM приватного ключа",
			})
		}
	}
	if format == "zip" || serverId != "" {
		// Создаем ZIP архив
		var buf bytes.Buffer
		zipWriter := zip.NewWriter(&buf)

		// Добавляем Sub CA сертификат
		subCAFile, err := zipWriter.Create(subCAFileName)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка создания архива",
			})
		}

		_, err = subCAFile.Write([]byte(subCACert))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка записи Sub CA в архив",
			})
		}

		// Добавляем Root CA сертификат
		rootCAFile, err := zipWriter.Create(rootCAFileName)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка создания архива",
			})
		}
		_, err = rootCAFile.Write([]byte(rootCACert))
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка записи Root CA в архив",
			})
		}

		if serverId != "" {
			// Добавляем публичный ключ (сертификат)
			publicKeyFile, err := zipWriter.Create(*domain + ".crt")
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка создания файла сертификата в архиве",
				})
			}
			_, err = publicKeyFile.Write([]byte(*publicKey))
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка записи сертификата в архив",
				})
			}

			// Добавляем приватный ключ
			privateKeyFile, err := zipWriter.Create(*domain + ".key")
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка создания файла приватного ключа в архиве",
				})
			}
			_, err = privateKeyFile.Write(decryptedKey)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка записи приватного ключа в архив",
				})
			}
		}
		if entityId != "" {
			// Добавляем публичный ключ (сертификат)
			publicKeyFile, err := zipWriter.Create(*commonName + ".crt")
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка создания файла сертификата в архиве",
				})
			}
			_, err = publicKeyFile.Write([]byte(*publicKey))
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка записи сертификата в архив",
				})
			}
			// Добавляем приватный ключ
			privateKeyFile, err := zipWriter.Create(*commonName + ".key")
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка создания файла приватного ключа в архиве",
				})
			}
			_, err = privateKeyFile.Write(decryptedKey)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка записи приватного ключа в архив",
				})
			}
		}

		// Закрываем ZIP writer
		err = zipWriter.Close()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка закрытия архива",
			})
		}
		var fileName string
		if serverId != "" {
			// Устанавливаем заголовки для скачивания файла
			fileName = fmt.Sprintf("certificate_%s.zip", *domain)
		}
		if entityId != "" {
			// Устанавливаем заголовки для скачивания файла
			fileName = fmt.Sprintf("certificate_%s.zip", *commonName)
		}
		c.Set("Content-Type", "application/zip")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
		c.Set("Content-Length", fmt.Sprintf("%d", buf.Len()))

		// Отправляем ZIP архив пользователю
		return c.Send(buf.Bytes())
	}

	if entityId != "" && (format == "pkcs12" || format == "pkcs12-legacy") {
		var password string
		// Если это пользовательский сертификат, получаем пароль из базы данных
		var encryptedPassword string
		err = db.Get(&encryptedPassword, "SELECT password FROM user_certs WHERE entity_id = ? and id = ?", entityId, id)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": fmt.Sprintf("Не удалось получить пароль для сертификата: %v", err),
			})
		}

		// Расшифровываем пароль
		decryptedPassword, err := aes.Decrypt([]byte(encryptedPassword), crypts.AesSecretKey.Key)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка расшифровки пароля",
			})
		}
		password = string(decryptedPassword)

		// Декодируем сертификат из PEM формата
		certBlock, _ := pem.Decode([]byte(*publicKey))
		if certBlock == nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Не удалось декодировать PEM сертификата",
			})
		}

		// Парсим сертификат
		cert, err := x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": fmt.Sprintf("Не удалось распарсить сертификат: %v", err),
			})
		}

		// Парсим приватный ключ
		privateKey, err := x509.ParsePKCS1PrivateKey(subCAKeyBlock.Bytes)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": fmt.Sprintf("Не удалось распарсить приватный ключ: %v", err),
			})
		}

		// Парсим промежуточный сертификат
		subCABlock, _ := pem.Decode([]byte(subCACert))
		if subCABlock == nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Не удалось декодировать PEM промежуточного сертификата",
			})
		}

		subCACertObj, err := x509.ParseCertificate(subCABlock.Bytes)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": fmt.Sprintf("Не удалось распарсить промежуточный сертификат: %v", err),
			})
		}

		// Создаем PKCS12
		var p12Data []byte
		if format == "pkcs12" {
			p12Data, err = pkcs12.Modern.Encode(privateKey, cert, []*x509.Certificate{subCACertObj}, password)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": fmt.Sprintf("Не удалось создать PKCS12 сертификат (Modern формат): %v", err),
				})
			}
		}
		// Для совместимости с ПО, которое не поддерживает современный формат (mac os x)
		if format == "pkcs12-legacy" {
			p12Data, err = pkcs12.Legacy.Encode(privateKey, cert, []*x509.Certificate{subCACertObj}, password)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": fmt.Sprintf("Не удалось создать PKCS12 сертификат (Legacy формат): %v", err),
				})
			}
		}

		// Устанавливаем заголовки для скачивания файла
		fileName := fmt.Sprintf("certificate_%s.p12", *commonName)
		c.Set("Content-Type", "application/x-pkcs12")
		c.Set("Content-Disposition", fmt.Sprintf("attachment; filename=%s", fileName))
		c.Set("Content-Length", fmt.Sprintf("%d", len(p12Data)))

		// Отправляем P12 файл пользователю
		return c.Send(p12Data)
	}

	return c.Status(400).JSON(fiber.Map{
		"status":  "error",
		"message": "Неподдерживаемый формат",
	})
}
