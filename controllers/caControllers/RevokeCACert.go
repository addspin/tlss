package caControllers

import (
	"fmt"
	"log/slog"
	"time"

	"sync"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RevokeCACert(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for remove server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.CAData)

		c.Bind().JSON(data)
		slog.Info("type_ca data", "type_ca", data.TypeCA)

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
				"message": "Missing required fields: certificate ID or server ID",
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
					"message": "root ca: Error updating certificate revocation mark: " + err.Error(),
				})
			}

			// Отзываем все сертификаты подписанные CA
			// Удаляем все отозванные клиентские сертификаты
			_, err = tx.Exec(`DELETE FROM user_certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Error deleting revoked client certificates: " + err.Error(),
				})
			}

			// Удаляем все отозванные серверные сертификаты
			_, err = tx.Exec(`DELETE FROM certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Error deleting revoked server certificates: " + err.Error(),
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
					"message": "Error revoking server certificates: " + err.Error(),
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
					"message": "Error revoking client certificates: " + err.Error(),
				})
			}

			// Коммитим текущую транзакцию перед пересозданием сертификатов
			err = tx.Commit()
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "RevokeCACertWithData: root ca: Error saving changes before recreating certificates: " + err.Error(),
				})
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
					"message": "sub ca: Error updating certificate revocation mark: " + err.Error(),
				})
			}

			// Удаляем все отозванные клиентские сертификаты
			_, err = tx.Exec(`DELETE FROM user_certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Error deleting revoked client certificates: " + err.Error(),
				})
			}

			// Удаляем все отозванные серверные сертификаты
			_, err = tx.Exec(`DELETE FROM certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
			if err != nil {
				tx.Rollback() // Откатываем транзакцию при ошибке
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "Error deleting revoked server certificates: " + err.Error(),
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
					"message": "Error revoking server certificates: " + err.Error(),
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
					"message": "Error revoking client certificates: " + err.Error(),
				})
			}

			// Коммитим текущую транзакцию перед пересозданием сертификатов
			err = tx.Commit()
			if err != nil {
				return c.Status(500).JSON(fiber.Map{
					"status":  "error",
					"message": "RevokeCACertWithData: sub ca: Error saving changes before recreating certificates: " + err.Error(),
				})
			}
		}
	}

	return c.Render("ca/certCAList-tpl", fiber.Map{})
}

// Функция вызываемая при создании CA RSA сертификатов
func CreateCACertRSA(data *models.CAData, db *sqlx.DB) error {
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
			return fmt.Errorf("RevokeCACertWithData root ca: Error updating certificate revocation mark: %w", err)
		}

		// Валидные сертификаты будут пересозданы, отозванные - удалены
		// Коммитим текущую транзакцию перед пересозданием сертификатов
		err = tx.Commit()
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: Error saving changes before recreating certificates: %w", err)
		}

		// Пересоздаем Root CA и Sub CA
		err = crypts.GenerateRSARootCA(data, db)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: Error generating Root CA: %w", err)
		}

		// 2) Пересоздание валидных сертфикатов
		// Получаем все валидные сертификаты для пересоздания с новыми CA
		certList := []models.CertsData{}
		err = db.Select(&certList, `SELECT id, algorithm, key_length, domain, common_name, country_name, san, state_province, locality_name, organization, organization_unit, email, save_on_server, cert_status, app_type, ttl, server_id, wildcard, reason_revoke, recreate, days_left 
			FROM certs 
			WHERE cert_status = ?`, validStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: error getting list of server certificates for recreation: %w", err)
		}

		// Требуется кэшировать запросы к БД для получения CA
		numWorkers := len(certList)

		// Обрабатываем серверные сертификаты
		err = processServerCertificates(certList, db, numWorkers)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: %w", err)
		}

		// Получаем все валидные клиентские сертификаты для пересоздания
		userCertList := []models.UserCertsData{}
		err = db.Select(&userCertList, `SELECT id, entity_id, algorithm, key_length, san, oid, oid_values, common_name, country_name, state_province, locality_name, organization, organization_unit, email, ttl, recreate, reason_revoke, days_left, password 
			FROM user_certs 
			WHERE cert_status = ?`, validStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: error getting list of client certificates for recreation: %w", err)
		}

		// Обрабатываем пользовательские сертификаты
		err = processUserCertificates(userCertList, db, numWorkers)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: %w", err)
		}

		// 3) Удаление отозванных и просроченных сертификатов подписанных старым CA
		// Удаляем все отозванные и просроченные клиентские сертификаты
		_, err = db.Exec(`DELETE FROM user_certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: error deleting revoked client certificates: %w", err)
		}

		// Удаляем все отозванные и просроченные серверные сертификаты
		_, err = db.Exec(`DELETE FROM certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: root ca: error deleting revoked server certificates: %w", err)
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
			return fmt.Errorf("RevokeCACertWithData: sub ca: Error updating certificate revocation mark: %w", err)
		}

		// Валидные сертификаты будут пересозданы, отозванные - удалены

		// Коммитим текущую транзакцию перед пересозданием сертификатов
		err = tx.Commit()
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: Error saving changes before recreating certificates: %w", err)
		}

		// Пересоздаем Sub CA
		err = crypts.GenerateRSASubCA(data, db)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: Error generating Sub CA: %w", err)
		}

		// 2) Пересоздание валидных сертфикатов
		// Получаем все валидные сертификаты для пересоздания с новыми CA
		certList := []models.CertsData{}
		err = db.Select(&certList, `SELECT id, algorithm, key_length, domain, common_name, country_name, san, state_province, locality_name, organization, organization_unit, email, save_on_server, cert_status, app_type, ttl, server_id, wildcard, reason_revoke, recreate, days_left 
			FROM certs 
			WHERE cert_status = ?`, validStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: error getting list of server certificates for recreation: %w", err)
		}

		numWorkers := len(certList)

		// Обрабатываем серверные сертификаты
		err = processServerCertificates(certList, db, numWorkers)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: %w", err)
		}

		// Получаем все валидные клиентские сертификаты для пересоздания
		userCertList := []models.UserCertsData{}
		err = db.Select(&userCertList, `SELECT id, entity_id, algorithm, key_length, san, oid, oid_values, common_name, country_name, state_province, locality_name, organization, organization_unit, email, ttl, recreate, reason_revoke, days_left, password 
			FROM user_certs 
			WHERE cert_status = ?`, validStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: error getting list of client certificates for recreation: %w", err)
		}

		// Обрабатываем пользовательские сертификаты
		err = processUserCertificates(userCertList, db, numWorkers)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: %w", err)
		}

		// 3) Удаление отозванных и просроченных сертификатов подписанных старым CA
		// Удаляем все отозванные и просроченные клиентские сертификаты
		_, err = db.Exec(`DELETE FROM user_certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: error deleting revoked client certificates: %w", err)
		}

		// Удаляем все отозванные и просроченные серверные сертификаты
		_, err = db.Exec(`DELETE FROM certs WHERE cert_status IN (?, ?)`, revokeStatus, expiredStatus)
		if err != nil {
			return fmt.Errorf("RevokeCACertWithData: sub ca: error deleting revoked server certificates: %w", err)
		}
		return nil
	}
	return fmt.Errorf("RevokeCACertWithData: unsupported CA type: %s", typeCA)
}

// Функция для обработки server certificates
func processServerCertificates(certList []models.CertsData, db *sqlx.DB, numWorkers int) error {
	if len(certList) == 0 {
		return nil
	}

	serverJobs := make(chan models.CertsData, len(certList))
	serverResultsErrors := make(chan error, len(certList))
	// var dbMutex sync.Mutex

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
					// dbMutex.Lock()
					certPEM, keyPEM, certErr = crypts.RecreateRSACertificate(&cert, db)
					// dbMutex.Unlock()

					if certErr != nil {
						serverResultsErrors <- fmt.Errorf("error generating RSA certificates: %w", certErr)
						continue
					}
					if cert.SaveOnServer {
						saveOnServer := crypts.NewSaveOnServer()
						// dbMutex.Lock()
						err := saveOnServer.SaveOnServer(&cert, db, certPEM, keyPEM)
						// dbMutex.Unlock()
						if err != nil {
							slog.Error("Error saving certificate to server", "error", err)
						}
					}
					serverResultsErrors <- nil
				case "ED25519":
					// dbMutex.Lock()
					certPEM, keyPEM, certErr = crypts.RecreateED25519Certificate(&cert, db)
					// dbMutex.Unlock()

					if certErr != nil {
						serverResultsErrors <- fmt.Errorf("error generating ED25519 certificates: %w", certErr)
						continue
					}
					if cert.SaveOnServer {
						saveOnServer := crypts.NewSaveOnServer()
						// dbMutex.Lock()
						err := saveOnServer.SaveOnServer(&cert, db, certPEM, keyPEM)
						// dbMutex.Unlock()
						if err != nil {
							slog.Error("Error saving certificate to server", "error", err)
						}
					}
					serverResultsErrors <- nil
				case "ECDSA":
					// dbMutex.Lock()
					certPEM, keyPEM, certErr = crypts.RecreateECDSACertificate(&cert, db)
					// dbMutex.Unlock()

					if certErr != nil {
						serverResultsErrors <- fmt.Errorf("error generating ECDSA certificates: %w", certErr)
						continue
					}
					if cert.SaveOnServer {
						saveOnServer := crypts.NewSaveOnServer()
						// dbMutex.Lock()
						err := saveOnServer.SaveOnServer(&cert, db, certPEM, keyPEM)
						// dbMutex.Unlock()
						if err != nil {
							slog.Error("Error saving certificate to server", "error", err)
						}
					}
				default:
					serverResultsErrors <- fmt.Errorf("unsupported algorithm: %s", cert.Algorithm)
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
			slog.Error("Error processing server certificate", "error", err)
		}
		return fmt.Errorf("errors found while processing %d server certificates", len(errors))
	}

	return nil
}

// Функция для обработки user certificates
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
					certErr = crypts.RecreateUserRSACertificate(&userCert, db)
					dbMutex.Unlock()
					userResultsErrors <- certErr
				case "ED25519":
					dbMutex.Lock()
					certErr = crypts.RecreateUserED25519Certificate(&userCert, db)
					dbMutex.Unlock()
					userResultsErrors <- certErr
				case "ECDSA":
					dbMutex.Lock()
					certErr = crypts.RecreateUserECDSACertificate(&userCert, db)
					dbMutex.Unlock()
					userResultsErrors <- certErr
				default:
					userResultsErrors <- fmt.Errorf("unsupported algorithm: %s", userCert.Algorithm)
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
			slog.Error("Error processing user certificate", "error", err)
		}
		return fmt.Errorf("RevokeCACertWithData: errors found while processing %d user certificates", len(userErrors))
	}

	return nil
}
