package controllers

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	ocsplib "golang.org/x/crypto/ocsp"
)

// HandleOCSP обрабатывает OCSP-запросы через Fiber
func HandleOCSP(ctx fiber.Ctx) error {
	// Создаем соединение с базой данных
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Printf("Ошибка подключения к базе данных: %v", err)
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка подключения к базе данных",
			"data":    err.Error(),
		})
	}
	defer db.Close()

	// Определяем интервал обновления для кеширования
	updateInterval := time.Duration(viper.GetInt("ocsp.updateInterval")) * time.Hour

	// Получаем OCSP-запрос
	var ocspRequestBytes []byte

	switch ctx.Method() {
	case "GET":
		// Обработка GET-запросов
		path := ctx.Params("*")
		if path == "" {
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"status":  "error",
				"message": "Некорректный OCSP-запрос: пустой путь",
			})
		}

		// Декодируем данные из URL
		ocspRequestBytes, err = hex.DecodeString(path)
		if err != nil {
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"status":  "error",
				"message": "Ошибка декодирования OCSP-запроса",
				"data":    err.Error(),
			})
		}
	case "POST":
		// Обработка POST-запросов
		ocspRequestBytes = ctx.Body()
		if len(ocspRequestBytes) == 0 {
			return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
				"status":  "error",
				"message": "Пустое тело запроса",
			})
		}
	default:
		return ctx.Status(fiber.StatusMethodNotAllowed).JSON(fiber.Map{
			"status":  "error",
			"message": "Метод не поддерживается",
		})
	}

	// Парсим OCSP-запрос
	ocspRequest, err := ocsplib.ParseRequest(ocspRequestBytes)
	if err != nil {
		log.Printf("Ошибка парсинга OCSP-запроса: %v", err)
		return ctx.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка парсинга OCSP-запроса",
			"data":    err.Error(),
		})
	}

	// Получаем серийный номер сертификата
	serialNumber := fmt.Sprintf("%X", ocspRequest.SerialNumber)
	log.Printf("Получен OCSP-запрос для сертификата с серийным номером: %s", serialNumber)

	// Получаем информацию о статусе сертификата из базы данных
	status, revokedAt, revocationReason, err := GetCertificateStatus(db, serialNumber)
	if err != nil {
		log.Printf("Ошибка получения статуса сертификата: %v", err)
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка получения статуса сертификата",
			"data":    err.Error(),
		})
	}

	// Загружаем необходимые сертификаты и ключи
	subCACert, ocspCert, ocspKey, err := LoadCertificatesAndKeys(db)
	if err != nil {
		log.Printf("Ошибка загрузки сертификатов и ключей: %v", err)
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка загрузки сертификатов и ключей",
			"data":    err.Error(),
		})
	}

	// Создаем шаблон ответа
	now := time.Now().UTC()
	nextUpdate := now.Add(updateInterval)

	template := ocsplib.Response{
		Status:             status,
		SerialNumber:       ocspRequest.SerialNumber,
		ThisUpdate:         now,
		NextUpdate:         nextUpdate,
		SignatureAlgorithm: ocspCert.SignatureAlgorithm,
	}

	if status == ocsplib.Revoked {
		template.RevokedAt = revokedAt
		template.RevocationReason = revocationReason
	}

	// Создаем и подписываем OCSP-ответ
	response, err := ocsplib.CreateResponse(subCACert, ocspCert, template, ocspKey)
	if err != nil {
		log.Printf("Ошибка создания OCSP-ответа: %v", err)
		return ctx.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка создания OCSP-ответа",
			"data":    err.Error(),
		})
	}

	// OCSP-ответы должны быть в бинарном формате, не в JSON
	// Отправляем ответ клиенту
	ctx.Set("Content-Type", "application/ocsp-response")
	ctx.Set("Cache-Control", fmt.Sprintf("max-age=%d", int(updateInterval.Seconds())))

	return ctx.Send(response)
}

// GetCertificateStatus получает статус сертификата из базы данных
func GetCertificateStatus(db *sqlx.DB, serialNumber string) (int, time.Time, int, error) {
	var status int
	var revokedAt time.Time
	var revocationReason int

	// Сначала ищем в таблице ocsp_cert
	var ocspCert models.OCSPCertificate
	err := db.Get(&ocspCert, `
		SELECT cert_status, reason_revoke, data_revoke 
		FROM ocsp_cert 
		WHERE serial_number = ? 
		LIMIT 1`, serialNumber)

	if err == nil {
		// Сертификат найден в таблице ocsp_cert
		switch ocspCert.CertStatus {
		case 0: // valid
			status = ocsplib.Good
		case 1: // expired
			status = ocsplib.Good // Истекшие сертификаты не считаются отозванными
		case 2: // revoked
			status = ocsplib.Revoked

			// Парсим время отзыва
			if ocspCert.DataRevoke != "" {
				revokedAt, _ = time.Parse("02.01.2006 15:04:05", ocspCert.DataRevoke)
			} else {
				revokedAt = time.Now()
			}

			revocationReason = parseRevocationReason(ocspCert.ReasonRevoke)
		default:
			status = ocsplib.Unknown
		}
	} else {
		// Если не найден в ocsp_cert, ищем в таблице certs
		var cert models.Certs
		err = db.Get(&cert, `
			SELECT cert_status, reason_revoke, data_revoke
			FROM certs
			WHERE serial_number = ?`, serialNumber)

		if err == nil {
			// Сертификат найден в таблице certs
			switch cert.CertStatus {
			case 0: // valid
				status = ocsplib.Good
			case 1: // expired
				status = ocsplib.Good // Истекшие сертификаты не считаются отозванными
			case 2: // revoked
				status = ocsplib.Revoked

				// Парсим время отзыва
				if cert.DataRevoke != "" {
					revokedAt, err = time.Parse("02.01.2006 15:04:05", cert.DataRevoke)
					if err != nil {
						revokedAt = time.Now()
					}
				} else {
					revokedAt = time.Now()
				}

				// Определяем причину отзыва
				revocationReason = parseRevocationReason(cert.ReasonRevoke)
			default:
				status = ocsplib.Unknown
			}
		} else {
			// Если сертификат не найден, считаем его действительным
			status = ocsplib.Good
		}
	}

	return status, revokedAt, revocationReason, nil
}

// LoadCertificatesAndKeys загружает сертификаты и ключи, необходимые для OCSP-ответа
func LoadCertificatesAndKeys(db *sqlx.DB) (*x509.Certificate, *x509.Certificate, *rsa.PrivateKey, error) {
	// Загружаем промежуточный сертификат CA
	var subCA models.SubCA
	err := db.Get(&subCA, "SELECT * FROM sub_ca_tlss WHERE id = 1")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("не удалось получить промежуточный CA: %v", err)
	}

	if subCA.SubCAStatus != 0 {
		return nil, nil, nil, fmt.Errorf("промежуточный CA недействителен")
	}

	// Декодируем сертификат промежуточного CA
	subCACertBlock, _ := pem.Decode([]byte(subCA.PublicKey))
	if subCACertBlock == nil {
		return nil, nil, nil, fmt.Errorf("не удалось декодировать сертификат промежуточного CA")
	}

	subCACert, err := x509.ParseCertificate(subCACertBlock.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("не удалось разобрать сертификат промежуточного CA: %v", err)
	}

	// Загружаем OCSP-сертификат
	var ocspCertData models.OCSPCertificate
	err = db.Get(&ocspCertData, "SELECT * FROM ocsp_cert WHERE cert_status = 0 AND ocsp_signing_eku = true LIMIT 1")
	if err != nil {
		return nil, nil, nil, fmt.Errorf("не удалось загрузить OCSP-сертификат: %v", err)
	}

	// Декодируем публичный ключ OCSP-сертификата
	ocspCertBlock, _ := pem.Decode([]byte(ocspCertData.PublicKey))
	if ocspCertBlock == nil {
		return nil, nil, nil, fmt.Errorf("не удалось декодировать публичный ключ OCSP-сертификата")
	}

	ocspCert, err := x509.ParseCertificate(ocspCertBlock.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("не удалось разобрать OCSP-сертификат: %v", err)
	}

	// Расшифровываем и декодируем приватный ключ OCSP-сертификата
	aes := crypts.Aes{}
	decryptedKey, err := aes.Decrypt([]byte(ocspCertData.PrivateKey), crypts.AesSecretKey.Key)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("не удалось расшифровать приватный ключ OCSP-сертификата: %v", err)
	}

	keyBlock, _ := pem.Decode(decryptedKey)
	if keyBlock == nil {
		return nil, nil, nil, fmt.Errorf("не удалось декодировать приватный ключ OCSP-сертификата")
	}

	ocspKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("не удалось разобрать приватный ключ OCSP-сертификата: %v", err)
	}

	return subCACert, ocspCert, ocspKey, nil
}

// parseRevocationReason преобразует текстовую причину отзыва в числовой код
func parseRevocationReason(reason string) int {
	switch reason {
	case "keyCompromise":
		return 1 // Компрометация ключа
	case "caCompromise":
		return 2 // Компрометация CA
	case "affiliationChanged":
		return 3 // Изменение принадлежности
	case "superseded":
		return 4 // Заменен
	case "cessationOfOperation":
		return 5 // Прекращение деятельности
	case "certificateHold":
		return 6 // Приостановка сертификата
	case "removeFromCRL":
		return 8 // Удаление из CRL
	case "privilegeWithdrawn":
		return 9 // Отзыв привилегий
	case "aaCompromise":
		return 10 // Компрометация AA
	default:
		return 0 // Не указана
	}
}
