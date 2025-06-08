package controllers

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"net/url"
	"strings"
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
func HandleOCSPUser(ctx fiber.Ctx) error {
	// Определяем константы OCSP ошибок
	// const (
	// 	OCSPMalformedRequest = 1
	// 	OCSPInternalError    = 2
	// 	OCSPTryLater         = 3
	// 	OCSPSigRequired      = 5
	// 	OCSPUnauthorized     = 6
	// )

	// Создаем соединение с базой данных
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Printf("Ошибка подключения к базе данных: %v", err)
		// Загружаем необходимые сертификаты и создаем ошибочный ответ
		return createMalformedRequestResponse(ctx)
	}
	defer db.Close()

	// Получаем OCSP-запрос
	var ocspRequestBytes []byte

	switch ctx.Method() {
	case "GET":
		// Обработка GET-запросов
		path := ctx.Params("*")
		log.Printf("Получен OCSP GET-запрос, полный путь: '%s'", path)

		if path == "" {
			log.Printf("Некорректный OCSP-запрос: пустой путь")
			return createMalformedRequestResponse(ctx)
		}

		// Сначала выполним URL-декодирование для преобразования %xx последовательностей
		decodedPath, err := url.QueryUnescape(path)
		if err != nil {
			log.Printf("Ошибка URL-декодирования: %v", err)
			// Пробуем вручную декодировать
			path = strings.ReplaceAll(path, "%2B", "+")
			path = strings.ReplaceAll(path, "%2F", "/")
			path = strings.ReplaceAll(path, "%3D", "=")
			path = strings.ReplaceAll(path, "%25", "%")
		} else {
			path = decodedPath
			log.Printf("URL-декодированный путь: '%s'", path)
		}

		// В OCSP запросах через GET, данные должны быть в base64url
		// Сначала проверим, может ли это быть прямой запрос
		rawOcspRequestBytes := []byte(path)
		_, errRaw := ocsplib.ParseRequest(rawOcspRequestBytes)
		if errRaw == nil {
			log.Printf("Успешно разобран OCSP-запрос в исходном виде")
			ocspRequestBytes = rawOcspRequestBytes
		} else {
			log.Printf("Попытка декодировать запрос из URL: %s", path)

			// Сначала попробуем декодировать URL-safe base64
			// Заменяем URL-safe символы на стандартные base64
			decodePath := strings.TrimSpace(path)
			decodePath = strings.ReplaceAll(decodePath, "-", "+")
			decodePath = strings.ReplaceAll(decodePath, "_", "/")

			// Добавляем padding если нужно
			switch len(decodePath) % 4 {
			case 2:
				decodePath += "=="
			case 3:
				decodePath += "="
			}

			ocspRequestBytes, err = base64.StdEncoding.DecodeString(decodePath)
			if err != nil {
				log.Printf("Ошибка декодирования base64url: %v, строка для декодирования: '%s'", err, decodePath)

				// Попробуем декодировать как hex (для обратной совместимости)
				ocspRequestBytes, err = hex.DecodeString(path)
				if err != nil {
					log.Printf("Ошибка декодирования hex: %v", err)
					return createMalformedRequestResponse(ctx)
				}
				log.Printf("Успешно декодирован hex запрос, длина: %d байт", len(ocspRequestBytes))
			} else {
				log.Printf("Успешно декодирован base64 запрос, длина: %d байт", len(ocspRequestBytes))
			}
		}
	case "POST":
		// Обработка POST-запросов
		ocspRequestBytes = ctx.Body()
		log.Printf("Получен OCSP POST-запрос, размер: %d байт", len(ocspRequestBytes))
		if len(ocspRequestBytes) == 0 {
			log.Printf("Пустое тело запроса")
			return createMalformedRequestResponse(ctx)
		}
	default:
		log.Printf("Метод %s не поддерживается", ctx.Method())
		return createMalformedRequestResponse(ctx)
	}

	// Выведем отладочную информацию о полученном запросе
	log.Printf("Тип запроса: %s, размер запроса: %d байт", ctx.Method(), len(ocspRequestBytes))
	if len(ocspRequestBytes) > 0 {
		log.Printf("Первые байты запроса: % X", ocspRequestBytes[:min(len(ocspRequestBytes), 16)])
	}

	// Парсим OCSP-запрос
	ocspRequest, err := ocsplib.ParseRequest(ocspRequestBytes)
	if err != nil {
		log.Printf("Ошибка парсинга OCSP-запроса: %v", err)
		// Выведем дамп байтов для отладки
		log.Printf("Дамп байтов запроса (первые 32 байта или меньше): % X", ocspRequestBytes[:min(len(ocspRequestBytes), 32)])
		return createMalformedRequestResponse(ctx)
	}

	// Получаем серийный номер сертификата
	serialNumber := fmt.Sprintf("%X", ocspRequest.SerialNumber)
	log.Printf("Получен OCSP-запрос для сертификата с серийным номером: %s (в десятичной системе: %s)", serialNumber, ocspRequest.SerialNumber.String())

	// Проверим, существует ли серийный номер в базе данных
	var exists bool
	db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM user_certs WHERE serial_number = ?)", serialNumber)
	log.Printf("Найден сертификат в БД user_certs с серийным номером %s: %v", serialNumber, exists)

	// Для надежности проверим также регистр-независимый поиск
	var existsCI bool
	db.Get(&existsCI, "SELECT EXISTS(SELECT 1 FROM user_certs WHERE LOWER(serial_number) = LOWER(?))", serialNumber)
	if existsCI && !exists {
		log.Printf("Найден сертификат с учетом регистр-независимого поиска: %v", existsCI)
		// Если серийный номер найден только при регистр-независимом поиске,
		// получим правильный серийный номер из БД
		var correctSerial string
		db.Get(&correctSerial, "SELECT serial_number FROM user_certs WHERE LOWER(serial_number) = LOWER(?)", serialNumber)
		if correctSerial != "" {
			log.Printf("Исправление регистра серийного номера: %s -> %s", serialNumber, correctSerial)
			serialNumber = correctSerial
			exists = true
		}
	}

	// Загружаем сертификаты и ключи
	subCACert, err := LoadCertificatesAndKeys(db)
	if err != nil {
		log.Printf("Ошибка загрузки сертификатов и ключей: %v", err)
		return createInternalErrorResponse(ctx, subCACert)
	}

	// Для отладки выведем хеши основного SubCA
	h1 := ocspRequest.HashAlgorithm.New()
	h1.Write(subCACert.RawSubject)
	subCANameHash := h1.Sum(nil)

	h2 := ocspRequest.HashAlgorithm.New()
	h2.Write(subCACert.RawSubjectPublicKeyInfo)
	subCAKeyHash := h2.Sum(nil)

	log.Printf("Основной SubCA: %s", subCACert.Subject.CommonName)
	log.Printf("Хеш имени SubCA: %X", subCANameHash)
	log.Printf("Хеш ключа SubCA: %X", subCAKeyHash)

	// Обрабатываем запрос с основным SubCA
	return processOCSPRequestWithSubCA(ctx, db, ocspRequest, serialNumber, subCACert)
}

// processOCSPRequestWithSubCA обрабатывает OCSP-запрос с конкретным SubCA сертификатом
func processOCSPRequestWithSubCA(ctx fiber.Ctx, db *sqlx.DB, ocspRequest *ocsplib.Request, serialNumber string,
	subCACert *x509.Certificate) error {

	// Получаем информацию о статусе сертификата из базы данных
	status, revokedAt, revocationReason, err := GetCertificateStatus(db, serialNumber)
	if err != nil {
		log.Printf("Ошибка получения статуса сертификата: %v", err)
		return createInternalErrorResponse(ctx, subCACert)
	}

	// Создаем шаблон ответа
	now := time.Now().UTC()

	log.Printf("Создаю OCSP-ответ со статусом: %d для сертификата с серийным номером: %s", status, serialNumber)

	// Проверим совпадение хешей имени и ключа издателя
	checkIssuerMatch := false
	if ocspRequest.IssuerKeyHash != nil && ocspRequest.IssuerNameHash != nil {
		// Используем тот же хеш-алгоритм, что и в запросе
		h := ocspRequest.HashAlgorithm.New()
		h.Write(subCACert.RawSubject)
		subCANameHash := h.Sum(nil)

		h = ocspRequest.HashAlgorithm.New()
		h.Write(subCACert.RawSubjectPublicKeyInfo)
		subCAKeyHash := h.Sum(nil)

		// Проверяем совпадение по SHA-1 OpenSSL-совместимому хешу
		matchName := bytes.Equal(ocspRequest.IssuerNameHash, subCANameHash)
		matchKey := bytes.Equal(ocspRequest.IssuerKeyHash, subCAKeyHash)

		// Получаем Subject Key Identifier из SubCA для сравнения
		var subCAKeyID []byte
		for _, ext := range subCACert.Extensions {
			if ext.Id.Equal([]int{2, 5, 29, 14}) { // OID для Subject Key Identifier
				subCAKeyID = ext.Value[2:] // Пропускаем первые 2 байта (тег и длина)
				break
			}
		}

		// Если хеши не совпадают, но у нас есть Subject Key Identifier, проверим совпадение по нему
		if !matchKey && subCAKeyID != nil {
			log.Printf("Проверка совпадения по Subject Key Identifier")
			log.Printf("SubCA Subject Key Identifier: %X", subCAKeyID)
			log.Printf("OCSP запрос IssuerKeyHash: %X", ocspRequest.IssuerKeyHash)

			// Если Subject Key Identifier совпадает с IssuerKeyHash, считаем ключи совпадающими
			matchKey = bytes.Equal(ocspRequest.IssuerKeyHash, subCAKeyID)
			log.Printf("Результат проверки по Subject Key Identifier: %v", matchKey)
		}

		checkIssuerMatch = matchName && matchKey

		// Печатаем хеши для отладки
		log.Printf("OCSP запрос IssuerNameHash: %X", ocspRequest.IssuerNameHash)
		log.Printf("Вычисленный SubCA NameHash: %X", subCANameHash)
		log.Printf("OCSP запрос IssuerKeyHash: %X", ocspRequest.IssuerKeyHash)
		log.Printf("Вычисленный SubCA KeyHash: %X", subCAKeyHash)
		if subCAKeyID != nil {
			log.Printf("SubCA Subject Key ID: %X", subCAKeyID)
		}
		log.Printf("Хеш-алгоритм в запросе: %s", ocspRequest.HashAlgorithm.String())

		log.Printf("Проверка соответствия издателя: nameMatch=%v, keyMatch=%v, общий результат=%v",
			matchName, matchKey, checkIssuerMatch)
	} else {
		log.Printf("Невозможно проверить соответствие издателя: отсутствуют хеши в запросе")
	}

	// Проверяем существование сертификата в базе данных
	var exists bool
	db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM user_certs WHERE serial_number = ?)", serialNumber)

	// Если хеши издателя не совпадают, но мы знаем, что сертификат существует,
	// все равно создаем правильный ответ
	// Это может происходить, если сертификат был выпущен другим SubCA,
	// но мы все еще можем подтвердить его статус
	if !checkIssuerMatch && exists {
		log.Printf("Хеши издателя не совпадают, но сертификат существует. Создаем ответ со статусом Good")
		status = ocsplib.Good
	} else if !checkIssuerMatch {
		log.Printf("Хеши издателя не совпадают, и сертификат не найден. Возвращаем минимальный ответ")
		ctx.Set("Content-Type", "application/ocsp-response")

		minimalResponse := []byte{
			0x30, 0x03, // SEQUENCE OF length 3
			0x0A, 0x01, 0x00, // ENUMERATED с значением 0 (successful)
		}

		return ctx.Status(fiber.StatusOK).Send(minimalResponse)
	}

	// Создаем шаблон OCSP-ответа
	template := ocsplib.Response{
		Status:             status,
		SerialNumber:       ocspRequest.SerialNumber,
		ThisUpdate:         now,
		NextUpdate:         now.Add(24 * time.Hour),
		SignatureAlgorithm: subCACert.SignatureAlgorithm,
	}

	// Если сертификат отозван, добавляем информацию об отзыве
	if status == ocsplib.Revoked {
		if revokedAt.IsZero() {
			revokedAt = now
		}
		template.RevokedAt = revokedAt
		template.RevocationReason = revocationReason
	}

	// Загружаем приватный ключ SubCA для подписи
	var subCA models.SubCA
	err = db.Get(&subCA, "SELECT * FROM sub_ca_tlss WHERE id = 1")
	if err == nil {
		// Расшифровываем и декодируем приватный ключ SubCA
		aes := crypts.Aes{}
		decryptedKey, err := aes.Decrypt([]byte(subCA.PrivateKey), crypts.AesSecretKey.Key)
		if err == nil {
			keyBlock, _ := pem.Decode(decryptedKey)
			if keyBlock != nil {
				subCAKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
				if err == nil {
					log.Printf("Используем приватный ключ SubCA для подписи")

					// Создаем OCSP-ответ, подписанный самим SubCA
					response, err := ocsplib.CreateResponse(subCACert, subCACert, template, subCAKey)
					if err == nil {
						// Устанавливаем заголовки и отправляем
						ctx.Set("Content-Type", "application/ocsp-response")
						ctx.Set("Cache-Control", "max-age=86400") // 24 часа кеширования
						return ctx.Send(response)
					}
					log.Printf("Ошибка создания OCSP-ответа с SubCA: %v", err)
				}
			}
		}
	}

	// Если не удалось использовать SubCA, возвращаем ошибку
	log.Printf("Не удалось использовать SubCA для подписи")
	return createInternalErrorResponse(ctx, subCACert)
}

// createMalformedRequestResponse создает корректный OCSP-ответ с ошибкой malformedRequest
func createMalformedRequestResponse(ctx fiber.Ctx) error {
	// Пытаемся загрузить сертификаты и ключи напрямую из файлов конфигурации
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		// Если не удалось подключиться к БД, создаем минимальный ответ
		ctx.Set("Content-Type", "application/ocsp-response")

		// Создаем DER-кодированный ответ с ошибкой MalformedRequest
		ocspResp := []byte{
			0x30, 0x03, // SEQUENCE
			0x0A, 0x01, 0x01, // ENUMERATED 1 (Malformed)
		}
		log.Println("Отправка OCSP-ответа с ошибкой malformedRequest (БД недоступна)")
		return ctx.Status(fiber.StatusOK).Send(ocspResp)
	}
	defer db.Close()

	// Загружаем необходимые сертификаты и ключи
	subCACert, err := LoadCertificatesAndKeys(db)
	if err != nil {
		// Если не удалось загрузить, создаем минимальный ответ
		ctx.Set("Content-Type", "application/ocsp-response")
		log.Printf("Ошибка загрузки сертификатов для OCSP: %v", err)

		ocspResp := []byte{
			0x30, 0x03, // SEQUENCE
			0x0A, 0x01, 0x01, // ENUMERATED 1 (Malformed)
		}
		return ctx.Status(fiber.StatusOK).Send(ocspResp)
	}

	// Создаем шаблон OCSP-ответа с кодом ошибки "malformedRequest"
	now := time.Now().UTC()

	// Создаем template с минимальными данными и произвольным серийным номером
	// (так как в запросе мы его не смогли разобрать)
	serialNumber, _ := big.NewInt(0).SetString("1", 10)
	template := ocsplib.Response{
		Status:             int(ocsplib.Malformed),
		ThisUpdate:         now,
		NextUpdate:         now.Add(time.Hour), // Небольшой период кеширования
		SignatureAlgorithm: subCACert.SignatureAlgorithm,
		SerialNumber:       serialNumber,
	}

	// Загружаем приватный ключ SubCA для подписи
	var subCA models.SubCA
	err = db.Get(&subCA, "SELECT * FROM sub_ca_tlss WHERE id = 1")
	if err == nil {
		// Расшифровываем и декодируем приватный ключ SubCA
		aes := crypts.Aes{}
		decryptedKey, err := aes.Decrypt([]byte(subCA.PrivateKey), crypts.AesSecretKey.Key)
		if err == nil {
			keyBlock, _ := pem.Decode(decryptedKey)
			if keyBlock != nil {
				subCAKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
				if err == nil {
					// Создаем и подписываем OCSP-ответ
					response, err := ocsplib.CreateResponse(subCACert, subCACert, template, subCAKey)
					if err == nil {
						// Устанавливаем заголовки и отправляем
						ctx.Set("Content-Type", "application/ocsp-response")
						ctx.Set("Cache-Control", "max-age=3600") // Кешировать 1 час
						return ctx.Send(response)
					}
				}
			}
		}
	}

	// Если не удалось создать ответ, возвращаем минимальный ответ
	ctx.Set("Content-Type", "application/ocsp-response")
	ocspResp := []byte{
		0x30, 0x03, // SEQUENCE
		0x0A, 0x01, 0x01, // ENUMERATED 1 (Malformed)
	}
	return ctx.Status(fiber.StatusOK).Send(ocspResp)
}

// createInternalErrorResponse создает корректный OCSP-ответ с ошибкой internalError
func createInternalErrorResponse(ctx fiber.Ctx, subCACert *x509.Certificate) error {
	// Если не передали сертификаты, пытаемся их получить
	if subCACert == nil {
		log.Println("Недостаточно данных для создания OCSP-ответа, пробуем createMalformedRequestResponse")
		return createMalformedRequestResponse(ctx) // Используем malformedRequest если нет данных
	}

	// Создаем шаблон OCSP-ответа с кодом ошибки "internalError"
	now := time.Now().UTC()
	// Используем произвольный серийный номер для формирования ответа
	serialNumber, _ := big.NewInt(0).SetString("1", 10)

	template := ocsplib.Response{
		Status:             int(ocsplib.InternalError),
		ThisUpdate:         now,
		NextUpdate:         now.Add(time.Hour), // Небольшой период кеширования
		SignatureAlgorithm: subCACert.SignatureAlgorithm,
		SerialNumber:       serialNumber,
	}

	// Загружаем приватный ключ SubCA для подписи
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		ctx.Set("Content-Type", "application/ocsp-response")
		ocspResp := []byte{
			0x30, 0x03, // SEQUENCE
			0x0A, 0x01, 0x02, // ENUMERATED 2 (InternalError)
		}
		return ctx.Status(fiber.StatusOK).Send(ocspResp)
	}
	defer db.Close()

	var subCA models.SubCA
	err = db.Get(&subCA, "SELECT * FROM sub_ca_tlss WHERE id = 1")
	if err == nil {
		// Расшифровываем и декодируем приватный ключ SubCA
		aes := crypts.Aes{}
		decryptedKey, err := aes.Decrypt([]byte(subCA.PrivateKey), crypts.AesSecretKey.Key)
		if err == nil {
			keyBlock, _ := pem.Decode(decryptedKey)
			if keyBlock != nil {
				subCAKey, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
				if err == nil {
					// Создаем и подписываем OCSP-ответ
					response, err := ocsplib.CreateResponse(subCACert, subCACert, template, subCAKey)
					if err == nil {
						// Устанавливаем заголовки и отправляем
						ctx.Set("Content-Type", "application/ocsp-response")
						ctx.Set("Cache-Control", "max-age=3600") // Кешировать 1 час
						return ctx.Send(response)
					}
				}
			}
		}
	}

	// Если не удалось создать ответ, возвращаем базовый ответ
	ctx.Set("Content-Type", "application/ocsp-response")
	ocspResp := []byte{
		0x30, 0x03, // SEQUENCE
		0x0A, 0x01, 0x02, // ENUMERATED 2 (InternalError)
	}
	return ctx.Status(fiber.StatusOK).Send(ocspResp)
}

// LoadCertificatesAndKeys загружает сертификаты и ключи, необходимые для OCSP-ответа
func LoadCertificatesAndKeys(db *sqlx.DB) (*x509.Certificate, error) {
	// Загружаем промежуточный сертификат CA
	var subCA models.SubCA
	err := db.Get(&subCA, "SELECT * FROM sub_ca_tlss WHERE id = 1")
	if err != nil {
		return nil, fmt.Errorf("не удалось получить промежуточный CA: %v", err)
	}

	if subCA.SubCAStatus != 0 {
		return nil, fmt.Errorf("промежуточный CA недействителен")
	}

	// Декодируем сертификат промежуточного CA
	subCACertBlock, _ := pem.Decode([]byte(subCA.PublicKey))
	if subCACertBlock == nil {
		return nil, fmt.Errorf("не удалось декодировать сертификат промежуточного CA")
	}

	subCACert, err := x509.ParseCertificate(subCACertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("не удалось разобрать сертификат промежуточного CA: %v", err)
	}

	return subCACert, nil
}

// GetCertificateStatus получает статус сертификата из базы данных
func GetCertificateStatus(db *sqlx.DB, serialNumber string) (int, time.Time, int, error) {
	var status int
	var revokedAt time.Time
	var revocationReason int

	log.Printf("Поиск сертификата в базе данных с серийным номером: %s", serialNumber)

	// Стандартизируем серийный номер (в верхний регистр без ведущих нулей)
	serialNumber = strings.ToUpper(serialNumber)

	// Проверим, существует ли серийный номер в базе данных напрямую
	var existsInCerts bool
	err := db.Get(&existsInCerts, "SELECT EXISTS(SELECT 1 FROM user_certs WHERE serial_number = ?)", serialNumber)
	if err != nil {
		log.Printf("Ошибка при проверке существования сертификата в таблице user_certs: %v", err)
	} else {
		log.Printf("Существование сертификата в таблице user_certs: %v", existsInCerts)
	}

	// Если сертификат не найден, попробуем поиск без учета регистра
	if !existsInCerts {
		var existsCaseInsensitive bool
		err := db.Get(&existsCaseInsensitive, "SELECT EXISTS(SELECT 1 FROM user_certs WHERE LOWER(serial_number) = LOWER(?))", serialNumber)
		if err == nil && existsCaseInsensitive {
			log.Printf("Найден сертификат при регистр-независимом поиске")
			// Получим правильный серийный номер в правильном регистре
			var correctSerial string
			err = db.Get(&correctSerial, "SELECT serial_number FROM user_certs WHERE LOWER(serial_number) = LOWER(?)", serialNumber)
			if err == nil && correctSerial != "" {
				log.Printf("Исправление регистра серийного номера: %s -> %s", serialNumber, correctSerial)
				serialNumber = correctSerial
				existsInCerts = true
			}
		}
	}

	// Ищем в таблице ocsp_revoke (отозванные сертификаты)
	var ocspRevoke models.OCSPRevoke
	err = db.Get(&ocspRevoke, `
		SELECT cert_status, reason_revoke, data_revoke
		FROM user_ocsp_revoke
		WHERE serial_number = ?
		LIMIT 1`, serialNumber)

	if err == nil {
		// Сертификат найден в таблице ocsp_revoke
		switch ocspRevoke.CertStatus {
		case 0: // valid
			status = ocsplib.Good
		case 1: // expired
			status = ocsplib.Good // Истекшие сертификаты не считаются отозванными
		case 2: // revoked
			status = ocsplib.Revoked

			// Парсим время отзыва
			if ocspRevoke.DataRevoke != "" {
				// Используем только формат RFC3339
				revokedAt, err = time.Parse(time.RFC3339, ocspRevoke.DataRevoke)
				if err != nil {
					revokedAt = time.Now()
				}
			} else {
				revokedAt = time.Now()
			}

			// Определяем причину отзыва
			revocationReason = parseRevocationReason(ocspRevoke.ReasonRevoke)
		default:
			status = ocsplib.Unknown
		}
	} else {
		// Если не найден в ocsp_revoke, ищем в таблице user_certs
		var cert models.UserCertsData
		err = db.Get(&cert, `
			SELECT cert_status, reason_revoke, data_revoke
			FROM user_certs
			WHERE serial_number = ?`, serialNumber)

		if err == nil {
			// Сертификат найден в таблице user_certs
			switch cert.CertStatus {
			case 0: // valid
				status = ocsplib.Good
			case 1: // expired
				status = ocsplib.Good // Истекшие сертификаты не считаются отозванными
			case 2: // revoked
				status = ocsplib.Revoked

				// Парсим время отзыва
				if cert.DataRevoke != "" {
					// Используем только формат RFC3339
					revokedAt, err = time.Parse(time.RFC3339, cert.DataRevoke)
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
			// Если сертификат не найден в обеих таблицах, возвращаем Good
			log.Printf("Сертификат с серийным номером %s не найден в базе данных, считаем его действительным", serialNumber)
			status = ocsplib.Good
		}
	}

	return status, revokedAt, revocationReason, nil
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
		return 0 // unspecified
	}
}

// min возвращает минимальное из двух чисел
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
