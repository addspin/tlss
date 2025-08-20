package caControllers

import (
	"fmt"
	"log"
	"time"

	"sync"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/addspin/tlss/utils"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RevokeCACert(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for remove server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.CAData)

		c.Bind().JSON(data)
		log.Println("type_ca data:", data.TypeCA)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.TypeCA == "" ||
			data.ReasonRevoke == "" {

			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Отсутствуют обязательные поля ID сертификата или ID сервера",
			})
		}
		tx := db.MustBegin()

		currentTime := time.Now().Format(time.RFC3339)
		reasonRevoke := data.ReasonRevoke
		typeCA := data.TypeCA
		revokeStatus := 2  // 2 - revoked
		validStatus := 0   // 0 - valid
		expiredStatus := 1 // 1 - expired

		// Перед вставкой нового сертификата помечаем текущий активный Root CA и Sub CA как отозванный
		if typeCA == "Root" {
			_, err := tx.Exec(`UPDATE ca_certs SET
				cert_status = ?,
				data_revoke = ?,
				reason_revoke = ?
				WHERE cert_status = ?`, revokeStatus, currentTime, reasonRevoke, validStatus)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "root ca: Ошибка при обновлении метки об отзыве сертификатов: " + err.Error(),
				})
			}

			// Отзываем все сертификаты подписанные CA

			// Удаляем все отозванные клиентские сертификаты
			_, err = tx.Exec(`DELETE FROM user_certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при удалении отозванных клиентских сертификатов: " + err.Error(),
				})
			}

			// Удаляем все отозванные серверные сертификаты
			_, err = tx.Exec(`DELETE FROM certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при удалении отозванных серверных сертификатов: " + err.Error(),
				})
			}

			// Помечаем все серверные сертификаты как отозванные
			_, err = tx.Exec(`UPDATE certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE cert_status IN (?, ?)`, revokeStatus, currentTime, reasonRevoke, expiredStatus, validStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при отзыве серверных сертификатов: " + err.Error(),
				})
			}

			// Помечаем все клиентские сертификаты как отозванные
			_, err = tx.Exec(`UPDATE user_certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE cert_status IN (?, ?)`, revokeStatus, currentTime, reasonRevoke, expiredStatus, validStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при отзыве клиентских сертификатов: " + err.Error(),
				})
			}

			// Пересоздаем Root CA и Sub CA
			crypts.GenerateRSARootCA(data, db)

			// Пересоздаем все сертификаты и сохраняем на сервере если такие имеются
			// получаем и пересоздаем все серверные сертификаты
			certList := []models.CertsData{}
			err = tx.Select(&certList, "SELECT algorithm, key_length, domain, common_name, country_name, san, state_province, locality_name, organization, organization_unit, email, save_on_server, server_status, app_type, ttl, server_id, wildcard, recreate, days_left FROM certs WHERE cert_status IN (?, ?)", expiredStatus, revokeStatus)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при получении списка серверов: " + err.Error(),
				})
			}

			for _, cert := range certList {
				var certPEM []byte
				var keyPEM []byte
				var certErr error
				switch cert.Algorithm {
				case "RSA":
					certPEM, keyPEM, certErr = crypts.GenerateRSACertificate(&cert, db)
					if certErr != nil {
						return c.Status(500).JSON(fiber.Map{
							"status":  "error",
							"message": "revoke ca: Ошибка генерации rsa сертификатов: " + certErr.Error(),
						})
					}
					if cert.SaveOnServer {
						saveOnServer := utils.NewSaveOnServer()
						err = saveOnServer.SaveOnServer(&cert, db, certPEM, keyPEM)
						if err != nil {
							log.Printf("revoke ca: Ошибка сохранения сертификата на сервер: %v", err)
						}
					}
				default:
					return c.Status(400).JSON(fiber.Map{
						"status":  "error",
						"message": "revoke ca: Неподдерживаемый алгоритм: " + cert.Algorithm,
					})
				}
			}

			// получаем и пересоздаем все клиентские сертификаты
			userCertList := []models.UserCertsData{}
			err = tx.Select(&userCertList, "SELECT algorithm, key_length, san, oid, oid_values, common_name, country_name, state_province, locality_name, organization, organization_unit, email, ttl, recreate, days_left, password FROM user_certs WHERE cert_status IN (?, ?)", expiredStatus, revokeStatus)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при получении списка клиентских сертификатов: " + err.Error(),
				})
			}
			for _, userCert := range userCertList {
				var certErr error
				switch userCert.Algorithm {
				case "RSA":
					_, _, certErr = crypts.GenerateUserRSACertificate(&userCert, db)
					if certErr != nil {
						return c.Status(500).JSON(fiber.Map{
							"status":  "error",
							"message": "revoke ca: Ошибка генерации rsa сертификатов: " + certErr.Error(),
						})
					}
				default:
					return c.Status(400).JSON(fiber.Map{
						"status":  "error",
						"message": "revoke ca: Неподдерживаемый алгоритм: " + userCert.Algorithm,
					})
				}
			}
		}

		if typeCA == "Sub" {
			// Перед вставкой нового сертификата помечаем текущий активный Sub CA как отозванный
			_, err = tx.Exec(`UPDATE ca_certs SET
			cert_status = ?,
			data_revoke = ?,
			reason_revoke = ?
			WHERE type_ca = ? AND cert_status = ?`, revokeStatus, currentTime, reasonRevoke, typeCA, validStatus)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "sub ca: Ошибка при обновлении метки об отзыве сертификатов: " + err.Error(),
				})
			}

			// Удаляем все отозванные клиентские сертификаты
			_, err = tx.Exec(`DELETE FROM user_certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при удалении отозванных клиентских сертификатов: " + err.Error(),
				})
			}

			// Удаляем все отозванные серверные сертификаты
			_, err = tx.Exec(`DELETE FROM certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при удалении отозванных серверных сертификатов: " + err.Error(),
				})
			}

			// Отзываем все сертификаты подписанные CA
			// Серверные сертификаты
			_, err = tx.Exec(`UPDATE certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE cert_status IN (?, ?)`, revokeStatus, currentTime, reasonRevoke, expiredStatus, validStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при отзыве серверных сертификатов: " + err.Error(),
				})
			}

			// Клиентские сертификаты
			_, err = tx.Exec(`UPDATE user_certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE cert_status IN (?, ?)`, revokeStatus, currentTime, reasonRevoke, expiredStatus, validStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при отзыве клиентских сертификатов: " + err.Error(),
				})
			}

			// Пересоздаем Sub CA
			crypts.GenerateRSASubCA(data, db)

			// Пересоздаем все сертификаты и сохраняем на сервере если такие имеются
			// получаем и пересоздаем все серверные сертификаты
			certList := []models.CertsData{}
			err = tx.Select(&certList, "SELECT algorithm, key_length, domain, common_name, country_name, san, state_province, locality_name, organization, organization_unit, email, save_on_server, server_status, app_type, ttl, server_id, wildcard, recreate, days_left FROM certs WHERE cert_status IN (?, ?)", expiredStatus, revokeStatus)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при получении списка серверов: " + err.Error(),
				})
			}
			for _, cert := range certList {
				var certPEM []byte
				var keyPEM []byte
				var certErr error
				switch cert.Algorithm {
				case "RSA":
					certPEM, keyPEM, certErr = crypts.GenerateRSACertificate(&cert, db)
					if certErr != nil {
						return c.Status(500).JSON(fiber.Map{
							"status":  "error",
							"message": "revoke ca: Ошибка генерации rsa сертификатов: " + certErr.Error(),
						})
					}
					if cert.SaveOnServer {
						saveOnServer := utils.NewSaveOnServer()
						err = saveOnServer.SaveOnServer(&cert, db, certPEM, keyPEM)
						if err != nil {
							log.Printf("revoke ca: Ошибка сохранения сертификата на сервер: %v", err)
						}
					}
				default:
					return c.Status(400).JSON(fiber.Map{
						"status":  "error",
						"message": "revoke ca: Неподдерживаемый алгоритм: " + cert.Algorithm,
					})
				}
			}

			// получаем и пересоздаем все клиентские сертификаты
			userCertList := []models.UserCertsData{}
			err = tx.Select(&userCertList, "SELECT algorithm, key_length, san, oid, oid_values, common_name, country_name, state_province, locality_name, organization, organization_unit, email, ttl, recreate, days_left, password FROM user_certs WHERE cert_status IN (?, ?)", expiredStatus, revokeStatus)
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Ошибка при получении списка клиентских сертификатов: " + err.Error(),
				})
			}
			for _, userCert := range userCertList {
				var certErr error
				switch userCert.Algorithm {
				case "RSA":
					_, _, certErr = crypts.GenerateUserRSACertificate(&userCert, db)
					if certErr != nil {
						return c.Status(500).JSON(fiber.Map{
							"status":  "error",
							"message": "revoke ca: Ошибка генерации rsa сертификатов: " + certErr.Error(),
						})
					}
				default:
					return c.Status(400).JSON(fiber.Map{
						"status":  "error",
						"message": "revoke ca: Неподдерживаемый алгоритм: " + userCert.Algorithm,
					})
				}
			}
		}

		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "sub ca: Ошибка при отзыве сертификата: " + err.Error(),
			})
		}
		err = tx.Commit() // Проверяем ошибку при коммите
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "root/sub ca: Ошибка при сохранении изменений: " + err.Error(),
			})
		}
	}
	return c.Render("ca/certCAList-tpl", fiber.Map{})
}

func RevokeCACertWithData(data *models.CAData, db *sqlx.DB) error {
	tx := db.MustBegin()
	currentTime := time.Now().Format(time.RFC3339)
	reasonRevoke := data.ReasonRevoke
	typeCA := data.TypeCA
	revokeStatus := 2  // 2 - revoked
	validStatus := 0   // 0 - valid
	expiredStatus := 1 // 1 - expired

	// Перед вставкой нового сертификата помечаем текущий активный Root CA и Sub CA как отозванный
	if typeCA == "Root" {
		_, err := tx.Exec(`UPDATE ca_certs SET
				cert_status = ?,
				data_revoke = ?,
				reason_revoke = ?
				WHERE cert_status = ?`, revokeStatus, currentTime, reasonRevoke, validStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData root ca: Ошибка при обновлении метки об отзыве сертификатов: %w", err)
		}

		// Отзываем все сертификаты подписанные CA
		// Удаляем все отозванные клиентские сертификаты
		_, err = tx.Exec(`DELETE FROM user_certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return fmt.Errorf("RevokeCACertWithData: root ca: ошибка при удалении отозванных клиентских сертификатов: %w", err)
		}

		// Удаляем все отозванные серверные сертификаты
		_, err = tx.Exec(`DELETE FROM certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return fmt.Errorf("RevokeCACertWithData: root ca: ошибка при удалении отозванных серверных сертификатов: %w", err)
		}

		// Помечаем все серверные сертификаты как отозванные
		_, err = tx.Exec(`UPDATE certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE cert_status IN (?, ?)`, revokeStatus, currentTime, reasonRevoke, expiredStatus, validStatus)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return fmt.Errorf("RevokeCACertWithData: root ca: ошибка при отзыве серверных сертификатов: %w", err)
		}

		// Помечаем все клиентские сертификаты как отозванные
		_, err = tx.Exec(`UPDATE user_certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE cert_status IN (?, ?)`, revokeStatus, currentTime, reasonRevoke, expiredStatus, validStatus)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return fmt.Errorf("RevokeCACertWithData: root ca: ошибка при отзыве клиентских сертификатов: %w", err)
		}

		// Коммитим текущую транзакцию перед пересозданием сертификатов
		err = tx.Commit()
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: Ошибка при сохранении изменений перед пересозданием сертификатов: %w", err)
		}

		// Пересоздаем Root CA и Sub CA
		err = crypts.GenerateRSARootCA(data, db)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: Ошибка при генерации Root CA: %w", err)
		}

		// Пересоздаем все сертификаты и сохраняем на сервере если такие имеются
		// получаем и пересоздаем все серверные сертификаты
		certList := []models.CertsData{}
		err = db.Select(&certList, "SELECT algorithm, key_length, domain, common_name, country_name, san, state_province, locality_name, organization, organization_unit, email, save_on_server, cert_status, app_type, ttl, server_id, wildcard, reason_revoke, recreate, days_left FROM certs WHERE cert_status IN (?, ?)", expiredStatus, revokeStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: ошибка при получении списка серверных сертификатов: %w", err)
		}

		numWorkers := len(certList)
		if numWorkers == 0 {
			// Нет сертификатов для обработки
		} else {
			if numWorkers < 2 {
				numWorkers = 1

			} else if numWorkers%2 != 0 {
				numWorkers = (numWorkers - 1) / 2

			} else if numWorkers > 100 && numWorkers%2 != 0 {
				numWorkers = numWorkers / 2

			} else {
				numWorkers = 2
			}
		}

		// Обрабатываем серверные сертификаты
		err = processServerCertificates(certList, db, numWorkers)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: %w", err)
		}

		// получаем и пересоздаем все клиентские сертификаты
		userCertList := []models.UserCertsData{}
		err = db.Select(&userCertList, "SELECT algorithm, key_length, san, oid, oid_values, common_name, country_name, state_province, locality_name, organization, organization_unit, email, ttl, recreate, reason_revoke, days_left, password FROM user_certs WHERE cert_status IN (?, ?)", expiredStatus, revokeStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: ошибка при получении списка клиентских сертификатов: %w", err)
		}

		// Обрабатываем пользовательские сертификаты
		err = processUserCertificates(userCertList, db, numWorkers)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: %w", err)
		}
		return nil
	}

	if typeCA == "Sub" {
		// Перед вставкой нового сертификата помечаем текущий активный Sub CA как отозванный
		_, err := tx.Exec(`UPDATE ca_certs SET
			cert_status = ?,
			data_revoke = ?,
			reason_revoke = ?
			WHERE type_ca = ? AND cert_status = ?`, revokeStatus, currentTime, reasonRevoke, typeCA, validStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: Ошибка при обновлении метки об отзыве сертификатов: %w", err)
		}

		// Удаляем все отозванные клиентские сертификаты
		_, err = tx.Exec(`DELETE FROM user_certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return fmt.Errorf("RevokeCACertWithData: sub ca: ошибка при удалении отозванных клиентских сертификатов: %w", err)
		}

		// Удаляем все отозванные серверные сертификаты
		_, err = tx.Exec(`DELETE FROM certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return fmt.Errorf("RevokeCACertWithData: sub ca: ошибка при удалении отозванных серверных сертификатов: %w", err)
		}

		// Отзываем все сертификаты подписанные CA
		// Помечаем все серверные сертификаты как отозванные
		_, err = tx.Exec(`UPDATE certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE cert_status IN (?, ?)`, revokeStatus, currentTime, reasonRevoke, expiredStatus, validStatus)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return fmt.Errorf("RevokeCACertWithData: sub ca: ошибка при отзыве серверных сертификатов: %w", err)
		}

		// Помечаем все клиентские сертификаты как отозванные
		_, err = tx.Exec(`UPDATE user_certs SET 
			cert_status = ?, 
			data_revoke = ?, 
			reason_revoke = ? 
			WHERE cert_status IN (?, ?)`, revokeStatus, currentTime, reasonRevoke, expiredStatus, validStatus)
		if err != nil {
			tx.Rollback() // Откатываем транзакцию при ошибке
			return fmt.Errorf("RevokeCACertWithData: sub ca: ошибка при отзыве клиентских сертификатов: %w", err)
		}

		// Коммитим текущую транзакцию перед пересозданием сертификатов
		err = tx.Commit()
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: Ошибка при сохранении изменений перед пересозданием сертификатов: %w", err)
		}

		// Пересоздаем Sub CA
		err = crypts.GenerateRSASubCA(data, db)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: Ошибка при генерации Sub CA: %w", err)
		}

		// Пересоздаем все сертификаты и сохраняем на сервере если такие имеются
		// получаем и пересоздаем все серверные сертификаты
		certList := []models.CertsData{}
		err = db.Select(&certList, "SELECT algorithm, key_length, domain, common_name, country_name, san, state_province, locality_name, organization, organization_unit, email, save_on_server, cert_status, app_type, ttl, server_id, wildcard, reason_revoke, recreate, days_left FROM certs WHERE cert_status IN (?, ?)", expiredStatus, revokeStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: ошибка при получении списка серверных сертификатов: %w", err)
		}

		numWorkers := len(certList)
		if numWorkers%2 != 0 {
			numWorkers = (numWorkers - 1) / 2
		}
		if numWorkers > 100 && numWorkers%2 != 0 {
			numWorkers = numWorkers / 2
		}

		// Обрабатываем серверные сертификаты
		err = processServerCertificates(certList, db, numWorkers)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: %w", err)
		}

		// получаем и пересоздаем все клиентские сертификаты
		userCertList := []models.UserCertsData{}
		err = db.Select(&userCertList, "SELECT algorithm, key_length, san, oid, oid_values, common_name, country_name, state_province, locality_name, organization, organization_unit, email, ttl, recreate, reason_revoke, days_left, password FROM user_certs WHERE cert_status IN (?, ?)", expiredStatus, revokeStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: ошибка при получении списка клиентских сертификатов: %w", err)
		}

		// Обрабатываем пользовательские сертификаты
		err = processUserCertificates(userCertList, db, numWorkers)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: %w", err)
		}
		return nil
	}
	return fmt.Errorf("RevokeCACertWithData: неподдерживаемый тип CA: %s", typeCA)
}

// Функция для обработки серверных сертификатов
func processServerCertificates(certList []models.CertsData, db *sqlx.DB, numWorkers int) error {
	if len(certList) == 0 {
		return nil
	}

	serverJobs := make(chan models.CertsData, len(certList))
	serverResultsErrors := make(chan error, len(certList))
	var dbMutex sync.Mutex

	// Отправляем задания
	for _, cert := range certList {
		serverJobs <- cert
	}
	close(serverJobs)

	// Запускаем воркеры
	var wg sync.WaitGroup
	for w := 1; w <= numWorkers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for cert := range serverJobs {
				var certPEM []byte
				var keyPEM []byte
				var certErr error

				switch cert.Algorithm {
				case "RSA":
					dbMutex.Lock()
					certPEM, keyPEM, certErr = crypts.GenerateRSACertificate(&cert, db)
					dbMutex.Unlock()

					if certErr != nil {
						serverResultsErrors <- fmt.Errorf("ошибка генерации rsa сертификатов: %w", certErr)
						continue
					}
					if cert.SaveOnServer {
						saveOnServer := utils.NewSaveOnServer()
						dbMutex.Lock()
						err := saveOnServer.SaveOnServer(&cert, db, certPEM, keyPEM)
						dbMutex.Unlock()
						if err != nil {
							log.Printf("Ошибка сохранения сертификата на сервер: %v", err)
						}
					}
					serverResultsErrors <- nil
				default:
					serverResultsErrors <- fmt.Errorf("неподдерживаемый алгоритм: %s", cert.Algorithm)
				}
			}
		}()
	}

	// Ждем завершения и закрываем канал
	go func() {
		wg.Wait()
		close(serverResultsErrors)
	}()

	// Собираем ошибки
	var errors []error
	for err := range serverResultsErrors {
		if err != nil {
			errors = append(errors, err)
		}
	}

	if len(errors) > 0 {
		for _, err := range errors {
			log.Printf("Ошибка при обработке серверного сертификата: %v", err)
		}
		return fmt.Errorf("обнаружены ошибки при обработке %d серверных сертификатов", len(errors))
	}

	return nil
}

// Функция для обработки пользовательских сертификатов
func processUserCertificates(userCertList []models.UserCertsData, db *sqlx.DB, numWorkers int) error {
	if len(userCertList) == 0 {
		return nil
	}

	userJobs := make(chan models.UserCertsData, len(userCertList))
	userResultsErrors := make(chan error, len(userCertList))
	var dbMutex sync.Mutex

	// Отправляем задания
	for _, userCert := range userCertList {
		userJobs <- userCert
	}
	close(userJobs)

	// Запускаем воркеры
	var userWg sync.WaitGroup
	for w := 1; w <= numWorkers; w++ {
		userWg.Add(1)
		go func() {
			defer userWg.Done()
			for userCert := range userJobs {
				var certErr error
				switch userCert.Algorithm {
				case "RSA":
					dbMutex.Lock()
					_, _, certErr = crypts.GenerateUserRSACertificate(&userCert, db)
					dbMutex.Unlock()
					userResultsErrors <- certErr
				default:
					userResultsErrors <- fmt.Errorf("неподдерживаемый алгоритм: %s", userCert.Algorithm)
				}
			}
		}()
	}

	// ОДНА горутина для закрытия канала ПОСЛЕ завершения всех воркеров
	go func() {
		userWg.Wait()
		close(userResultsErrors)
	}()

	// Собираем ошибки ПОСЛЕ цикла создания воркеров
	var userErrors []error
	for err := range userResultsErrors {
		if err != nil {
			userErrors = append(userErrors, err)
		}
	}

	if len(userErrors) > 0 {
		for _, err := range userErrors {
			log.Printf("Ошибка при обработке пользовательского сертификата: %v", err)
		}
		return fmt.Errorf("RevokeCACertWithData: обнаружены ошибки при обработке %d пользовательских сертификатов", len(userErrors))
	}

	return nil
}
