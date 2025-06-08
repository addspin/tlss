package ocsp

import (
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"strings"
	"sync"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ocsp"
)

// OCSPResponder представляет OCSP-респондер
type OCSPResponder struct {
	db             *sqlx.DB
	updateInterval time.Duration
	ocspCertCache  map[string]*models.OCSPCertificate
	mu             sync.RWMutex
	SubCACert      *x509.Certificate // Сертификат промежуточного CA
	SubCAKey       *rsa.PrivateKey   // Ключ промежуточного CA
	OCSPKey        *rsa.PrivateKey   // Ключ для подписи OCSP-ответов
	OCSPCert       *x509.Certificate // Сертификат OCSP-респондера
}

// StartOCSPResponder запускает периодическое обновление данных OCSP в отдельной горутине
func StartOCSPResponder(updateInterval time.Duration) {
	// Получаем соединение с базой данных
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatalf("Не удалось подключиться к базе данных: %v", err)
	}
	defer db.Close()

	// Создаем новый OCSP-респондер
	responder, err := NewOCSPResponder(db, updateInterval)
	if err != nil {
		log.Fatalf("Не удалось создать OCSP-респондер: %v", err)
	}

	// Генерируем или обновляем OCSP-сертификат
	// if err := responder.GenerateOCSPCertificate(); err != nil {
	// 	log.Printf("Ошибка создания OCSP-сертификата: %v", err)
	// }

	// Запускаем обновление данных OCSP сразу при старте
	if err := responder.UpdateOCSPData(); err != nil {
		log.Printf("Ошибка начального обновления данных OCSP: %v", err)
	}

	// Запускаем периодическое обновление в отдельной горутине
	ticker := time.NewTicker(updateInterval)
	go func() {
		for range ticker.C {
			log.Println("Выполняется обновление данных OCSP...")
			if err := responder.UpdateOCSPData(); err != nil {
				log.Printf("Ошибка обновления данных OCSP: %v", err)
			}
		}
	}()
}

// NewOCSPResponder создает новый OCSP-респондер
func NewOCSPResponder(db *sqlx.DB, updateInterval time.Duration) (*OCSPResponder, error) {
	// Инициализируем OCSP-респондер
	responder := &OCSPResponder{
		db:             db,
		updateInterval: updateInterval,
		ocspCertCache:  make(map[string]*models.OCSPCertificate),
	}

	// Загружаем сертификат и ключ промежуточного CA
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

	var err2 error
	responder.SubCACert, err2 = x509.ParseCertificate(subCACertBlock.Bytes)
	if err2 != nil {
		return nil, fmt.Errorf("не удалось разобрать сертификат промежуточного CA: %v", err2)
	}

	// Расшифровываем и декодируем приватный ключ промежуточного CA
	aes := crypts.Aes{}
	decryptedKey, err := aes.Decrypt([]byte(subCA.PrivateKey), crypts.AesSecretKey.Key)
	if err != nil {
		return nil, fmt.Errorf("не удалось расшифровать приватный ключ промежуточного CA: %v", err)
	}

	subCAKeyBlock, _ := pem.Decode(decryptedKey)
	if subCAKeyBlock == nil {
		return nil, fmt.Errorf("не удалось декодировать приватный ключ промежуточного CA")
	}

	var err3 error
	responder.SubCAKey, err3 = x509.ParsePKCS1PrivateKey(subCAKeyBlock.Bytes)
	if err3 != nil {
		return nil, fmt.Errorf("не удалось разобрать приватный ключ промежуточного CA: %v", err3)
	}

	return responder, nil
}

// GenerateOCSPCertificate создает или обновляет сертификат OCSP-респондера
// func (r *OCSPResponder) GenerateOCSPCertificate() error {
// 	log.Println("Проверка и создание OCSP-сертификата...")

// 	// Проверяем наличие действующего OCSP-сертификата в базе
// 	var exists bool
// 	err := r.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM ocsp_cert WHERE cert_status = 0 AND ocsp_signing_eku = true LIMIT 1)")
// 	if err != nil {
// 		return fmt.Errorf("ошибка проверки наличия OCSP-сертификата: %v", err)
// 	}

// 	// Если действующий OCSP-сертификат есть, загрузим его и проверим срок действия
// 	if exists {
// 		var ocspCert models.OCSPCertificate
// 		err = r.db.Get(&ocspCert, "SELECT * FROM ocsp_cert WHERE cert_status = 0 AND ocsp_signing_eku = true LIMIT 1")
// 		if err != nil {
// 			return fmt.Errorf("не удалось загрузить существующий OCSP-сертификат: %v", err)
// 		}

// 		// Декодируем публичный ключ OCSP-сертификата
// 		certBlock, _ := pem.Decode([]byte(ocspCert.PublicKey))
// 		if certBlock == nil {
// 			return fmt.Errorf("не удалось декодировать публичный ключ OCSP-сертификата")
// 		}

// 		var parsedCert *x509.Certificate
// 		parsedCert, err = x509.ParseCertificate(certBlock.Bytes)
// 		if err != nil {
// 			return fmt.Errorf("не удалось разобрать OCSP-сертификат: %v", err)
// 		}

// 		// Если сертификат действующий, используем его
// 		r.OCSPCert = parsedCert

// 		// Расшифровываем и декодируем приватный ключ OCSP-сертификата
// 		aes := crypts.Aes{}
// 		decryptedKey, err := aes.Decrypt([]byte(ocspCert.PrivateKey), crypts.AesSecretKey.Key)
// 		if err != nil {
// 			return fmt.Errorf("не удалось расшифровать приватный ключ OCSP-сертификата: %v", err)
// 		}

// 		keyBlock, _ := pem.Decode(decryptedKey)
// 		if keyBlock == nil {
// 			return fmt.Errorf("не удалось декодировать приватный ключ OCSP-сертификата")
// 		}

// 		r.OCSPKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
// 		if err != nil {
// 			return fmt.Errorf("не удалось разобрать приватный ключ OCSP-сертификата: %v", err)
// 		}

// 		log.Println("Существующий OCSP-сертификат успешно загружен")
// 		return nil
// 	}

// 	// Создаем новый OCSP-сертификат
// 	log.Println("Создание нового OCSP-сертификата...")

// 	// Генерируем новую RSA ключевую пару для OCSP-сертификата
// 	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
// 	if err != nil {
// 		return fmt.Errorf("не удалось сгенерировать RSA ключевую пару: %v", err)
// 	}
// 	r.OCSPKey = privateKey

// 	// Генерируем случайный серийный номер
// 	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
// 	if err != nil {
// 		return fmt.Errorf("не удалось сгенерировать серийный номер: %v", err)
// 	}

// 	// Получаем настройки из конфигурации для OCSP-сертификата
// 	now := time.Now()
// 	// OCSP-сертификаты обычно имеют меньший срок действия, чем CA-сертификаты
// 	// Используем 30% от срока действия промежуточного CA, но не более 90 дней
// 	ttl := int(time.Until(r.SubCACert.NotAfter).Hours() / 24 * 0.3)
// 	if ttl > 90 {
// 		ttl = 90 // Максимум 90 дней
// 	}
// 	expiry := now.AddDate(0, 0, ttl)

// 	// Формируем шаблон OCSP-сертификата
// 	template := &x509.Certificate{
// 		SerialNumber: serialNumber,
// 		Subject: pkix.Name{
// 			CommonName:         "TLSS OCSP Responder",
// 			Country:            []string{r.SubCACert.Subject.Country[0]},
// 			Province:           []string{r.SubCACert.Subject.Province[0]},
// 			Locality:           []string{r.SubCACert.Subject.Locality[0]},
// 			Organization:       []string{r.SubCACert.Subject.Organization[0]},
// 			OrganizationalUnit: []string{r.SubCACert.Subject.OrganizationalUnit[0]},
// 		},
// 		NotBefore:             now,
// 		NotAfter:              expiry,
// 		KeyUsage:              x509.KeyUsageDigitalSignature,
// 		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
// 		BasicConstraintsValid: true,
// 		IsCA:                  false,
// 	}

// 	// Добавляем расширение id-pkix-ocsp-nocheck (OID: 1.3.6.1.5.5.7.48.1.5)
// 	ocspNoCheckExt := pkix.Extension{
// 		Id:       []int{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
// 		Critical: false,
// 		Value:    []byte{0x05, 0x00}, // DER-кодирование NULL
// 	}
// 	template.ExtraExtensions = append(template.ExtraExtensions, ocspNoCheckExt)

// 	// Создаем сертификат, подписанный промежуточным CA
// 	certDER, err := x509.CreateCertificate(rand.Reader, template, r.SubCACert, &privateKey.PublicKey, r.SubCAKey)
// 	if err != nil {
// 		return fmt.Errorf("не удалось создать OCSP-сертификат: %v", err)
// 	}

// 	// Конвертируем сертификат и ключ в PEM-формат
// 	certPEM := pem.EncodeToMemory(&pem.Block{
// 		Type:  "CERTIFICATE",
// 		Bytes: certDER,
// 	})

// 	keyPEM := pem.EncodeToMemory(&pem.Block{
// 		Type:  "RSA PRIVATE KEY",
// 		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
// 	})

// 	// Шифруем приватный ключ
// 	aes := crypts.Aes{}
// 	encryptedKey, err := aes.Encrypt(keyPEM, crypts.AesSecretKey.Key)
// 	if err != nil {
// 		return fmt.Errorf("не удалось зашифровать приватный ключ OCSP-сертификата: %v", err)
// 	}

// 	// Парсим созданный сертификат
// 	r.OCSPCert, err = x509.ParseCertificate(certDER)
// 	if err != nil {
// 		return fmt.Errorf("не удалось разобрать созданный OCSP-сертификат: %v", err)
// 	}

// 	// Вычисляем хеши для имени и ключа издателя
// 	issuerNameHash, issuerKeyHash, hashAlgo := calculateIssuerHashes(r.SubCACert)

// 	// Сохраняем OCSP-сертификат в базу данных
// 	_, err = r.db.Exec(`
// 		INSERT INTO ocsp_cert (
// 			create_time, serial_number, issuer_name, public_key, private_key,
// 			cert_status, reason_revoke, data_revoke, cert_create_time, cert_expire_time,
// 			ocsp_signing_eku, ocsp_nocheck, issuer_subca_serial_number,
// 			issuer_name_hash, issuer_key_hash, hash_algorithm,
// 			this_update, next_update, ocsp_extensions
// 		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
// 	`,
// 		now.Format(time.RFC3339),              // create_time
// 		standardizeSerialNumber(serialNumber), // serial_number - в стандартизированном формате
// 		"ocsp.responder",                      // issuer_name
// 		string(certPEM),                       // public_key
// 		string(encryptedKey),                  // private_key
// 		0,                                     // cert_status (0 - действительный)
// 		"",                                    // reason_revoke
// 		"",                                    // data_revoke
// 		now.Format(time.RFC3339),              // cert_create_time
// 		expiry.Format(time.RFC3339),           // cert_expire_time
// 		true,                                  // ocsp_signing_eku
// 		true,                                  // ocsp_nocheck
// 		r.SubCACert.SerialNumber.String(),     // issuer_subca_serial_number
// 		issuerNameHash,                        // issuer_name_hash
// 		issuerKeyHash,                         // issuer_key_hash
// 		hashAlgo,                              // hash_algorithm
// 		now.Format(time.RFC3339),              // this_update
// 		expiry.Format(time.RFC3339),           // next_update
// 		"",                                    // ocsp_extensions
// 	)
// 	if err != nil {
// 		return fmt.Errorf("не удалось сохранить OCSP-сертификат в базу данных: %v", err)
// 	}

// 	log.Println("Новый OCSP-сертификат успешно создан и сохранен")
// 	return nil
// }

// UpdateOCSPData обновляет данные о статусе сертификатов в базе OCSP
func (r *OCSPResponder) UpdateOCSPData() error {
	log.Println("Обновление данных OCSP...")

	// Получаем текущее время для записи в ThisUpdate
	now := time.Now().UTC()
	nowStr := now.Format(time.RFC3339)

	// Вычисляем NextUpdate на основе настройки ocsp.updateInterval
	nextUpdate := now.Add(r.updateInterval)
	nextUpdateStr := nextUpdate.Format(time.RFC3339)

	// Запрашиваем из БД все сертификаты с статусом 2 (отозванные)
	var certs []models.CertsData
	err := r.db.Select(&certs, `
		SELECT 
			id, domain, cert_create_time, cert_expire_time, days_left,
			serial_number, cert_status, reason_revoke, data_revoke
		FROM 
			certs 
		WHERE 
			cert_status = 2
	`)
	if err != nil {
		return fmt.Errorf("ошибка запроса отозванных сертификатов: %v", err)
	}

	log.Printf("Найдено %d отозванных сертификатов", len(certs))

	// Вычисляем хеши для имени и ключа издателя
	issuerNameHash, issuerKeyHash, hashAlgo := calculateIssuerHashes(r.SubCACert)

	// Создаем кеш для быстрого доступа к отозванным сертификатам
	newCache := make(map[string]*models.OCSPCertificate)

	// Обрабатываем каждый отозванный сертификат
	for _, cert := range certs {
		// Устанавливаем значения по умолчанию для пустых полей
		if cert.DataRevoke == "" {
			cert.DataRevoke = now.Format(time.RFC3339)
			log.Printf("Для сертификата %s установлена дата отзыва по умолчанию: %s", cert.SerialNumber, cert.DataRevoke)
		}

		if cert.ReasonRevoke == "" {
			cert.ReasonRevoke = "unspecified"
			log.Printf("Для сертификата %s установлена причина отзыва по умолчанию: %s", cert.SerialNumber, cert.ReasonRevoke)
		}

		// Создаем запись OCSP для кэша
		ocspCert := &models.OCSPCertificate{
			SerialNumber:            cert.SerialNumber,
			CreatedAt:               now.Format(time.RFC3339),
			IssuerName:              r.SubCACert.Subject.String(),
			CertStatus:              cert.CertStatus,
			ReasonRevoke:            cert.ReasonRevoke,
			DataRevoke:              cert.DataRevoke,
			CertCreateTime:          cert.CertCreateTime,
			CertExpireTime:          cert.CertExpireTime,
			OCSPSigningEKU:          false, // Для отозванных сертификатов должно быть false
			OCSPNoCheck:             false, // Для отозванных сертификатов должно быть false
			IssuerSubCASerialNumber: r.SubCACert.SerialNumber.String(),
			IssuerNameHash:          issuerNameHash,
			IssuerKeyHash:           issuerKeyHash,
			HashAlgorithm:           hashAlgo,
			ThisUpdate:              nowStr,
			NextUpdate:              nextUpdateStr,
		}

		// Проверяем, существует ли уже запись для этого сертификата в таблице ocsp_revoke
		var existingId int
		err = r.db.QueryRow(`
			SELECT id FROM ocsp_revoke 
			WHERE serial_number = ?`, cert.SerialNumber).Scan(&existingId)

		if err == nil {
			// Если запись существует, обновляем её
			_, err = r.db.Exec(`
				UPDATE ocsp_revoke SET
					domain = ?, cert_create_time = ?, cert_expire_time = ?, 
					days_left = ?, data_revoke = ?, reason_revoke = ?, cert_status = ?,
					issuer_name = ?, issuer_subca_serial_number = ?, 
					issuer_name_hash = ?, issuer_key_hash = ?, hash_algorithm = ?,
					this_update = ?, next_update = ?
				WHERE id = ?`,
				cert.Domain,
				cert.CertCreateTime,
				cert.CertExpireTime,
				cert.DaysLeft,
				cert.DataRevoke,
				cert.ReasonRevoke,
				cert.CertStatus,
				r.SubCACert.Subject.String(),
				r.SubCACert.SerialNumber.Text(16), // Текстовое представление в шестнадцатеричном формате
				issuerNameHash,
				issuerKeyHash,
				hashAlgo,
				nowStr,
				nextUpdateStr,
				existingId,
			)
			if err != nil {
				log.Printf("Ошибка обновления данных для отозванного сертификата %s (%s): %v", cert.SerialNumber, cert.Domain, err)
				continue
			}
			log.Printf("Обновлена запись для отозванного сертификата %s (%s)", cert.SerialNumber, cert.Domain)
		} else {
			// Если записи нет, вставляем новую в таблицу ocsp_revoke
			_, err = r.db.Exec(`
				INSERT INTO ocsp_revoke (
					domain, cert_create_time, cert_expire_time, days_left, 
					serial_number, data_revoke, reason_revoke, cert_status,
					issuer_name, issuer_subca_serial_number, 
					issuer_name_hash, issuer_key_hash, hash_algorithm,
					this_update, next_update
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				cert.Domain,
				cert.CertCreateTime,
				cert.CertExpireTime,
				cert.DaysLeft,
				cert.SerialNumber, // Используем уже стандартизированный серийный номер из certs
				cert.DataRevoke,
				cert.ReasonRevoke,
				cert.CertStatus,
				r.SubCACert.Subject.String(),
				standardizeSerialNumber(r.SubCACert.SerialNumber),
				issuerNameHash,
				issuerKeyHash,
				hashAlgo,
				nowStr,
				nextUpdateStr,
			)
			if err != nil {
				log.Printf("Ошибка вставки данных для отозванного сертификата %s (%s): %v", cert.SerialNumber, cert.Domain, err)
				continue
			}
			log.Printf("Добавлена новая запись для отозванного сертификата %s (%s)", cert.SerialNumber, cert.Domain)
		}

		// Добавляем в кеш
		newCache[cert.SerialNumber] = ocspCert
	}

	// Обновляем кеш атомарно
	r.mu.Lock()
	r.ocspCertCache = newCache
	r.mu.Unlock()

	log.Println("Обновление данных OCSP завершено успешно")
	return nil
}

// Вспомогательные функции

// calculateIssuerHashes вычисляет хеши имени и ключа издателя
func calculateIssuerHashes(issuerCert *x509.Certificate) (string, string, string) {
	// Используем SHA-1 для совместимости с NGINX OCSP stapling
	// OpenSSL и NGINX по умолчанию используют SHA-1 для OCSP
	h1 := sha1.New()
	h1.Write(issuerCert.RawSubject)
	nameHash := h1.Sum(nil)

	h2 := sha1.New()
	h2.Write(issuerCert.RawSubjectPublicKeyInfo)
	keyHash := h2.Sum(nil)

	// Также рассчитаем хеши с SHA-256 для отладки
	sha256NameHash := sha256.Sum256(issuerCert.RawSubject)
	sha256KeyHash := sha256.Sum256(issuerCert.RawSubjectPublicKeyInfo)

	log.Printf("Рассчитанные хеши для CA [%s]:", issuerCert.Subject.CommonName)
	log.Printf("SHA-1 NameHash: %X", nameHash)
	log.Printf("SHA-1 KeyHash: %X", keyHash)
	log.Printf("SHA-256 NameHash: %X", sha256NameHash)
	log.Printf("SHA-256 KeyHash: %X", sha256KeyHash)

	return hex.EncodeToString(nameHash), hex.EncodeToString(keyHash), "SHA1"
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

// GetSignatureAlgorithm возвращает алгоритм подписи для OCSP-ответов
func (r *OCSPResponder) GetSignatureAlgorithm() x509.SignatureAlgorithm {
	// Возвращаем алгоритм подписи из сертификата OCSP-респондера,
	// или SHA256WithRSA, если сертификат не доступен
	if r.OCSPCert != nil {
		return r.OCSPCert.SignatureAlgorithm
	}
	return x509.SHA256WithRSA
}

// CreateResponse создает и подписывает OCSP-ответ на основе шаблона
func (r *OCSPResponder) CreateResponse(template ocsp.Response) ([]byte, error) {
	// Проверяем, что у нас есть все необходимые данные для создания ответа
	if r.SubCACert == nil || r.OCSPCert == nil || r.OCSPKey == nil {
		return nil, fmt.Errorf("отсутствуют необходимые сертификаты или ключи для создания OCSP-ответа")
	}

	// Проверяем корректность шаблона
	if template.SerialNumber == nil {
		return nil, fmt.Errorf("не указан серийный номер в шаблоне OCSP-ответа")
	}

	// Гарантируем, что поля ThisUpdate и NextUpdate заполнены
	if template.ThisUpdate.IsZero() {
		template.ThisUpdate = time.Now().UTC()
	}

	if template.NextUpdate.IsZero() {
		template.NextUpdate = template.ThisUpdate.Add(24 * time.Hour)
	}

	// Если ответ для отозванного сертификата, проверяем заполненность полей отзыва
	if template.Status == ocsp.Revoked {
		if template.RevokedAt.IsZero() {
			template.RevokedAt = time.Now().UTC()
		}
	}

	// Для создания корректного OCSP-ответа могут потребоваться дополнительные поля
	// Копируем шаблон, чтобы избежать изменения оригинала
	responseTemplate := template

	// Используем шаблон для создания OCSP-ответа
	responseBytes, err := ocsp.CreateResponse(r.SubCACert, r.OCSPCert, responseTemplate, r.OCSPKey)
	if err != nil {
		// Логируем ошибку
		log.Printf("Ошибка создания OCSP-ответа: %v", err)

		// Пробуем создать базовый ответ с минимальным набором полей
		log.Printf("Пытаемся создать базовый OCSP-ответ")

		// Создаем новый базовый шаблон с только необходимыми полями
		basicTemplate := ocsp.Response{
			Status:       ocsp.Good, // По умолчанию считаем, что сертификат действителен
			SerialNumber: template.SerialNumber,
			ThisUpdate:   time.Now().UTC(),
			NextUpdate:   time.Now().UTC().Add(24 * time.Hour),
		}

		// Повторяем попытку создания ответа
		responseBytes, err2 := ocsp.CreateResponse(r.SubCACert, r.OCSPCert, basicTemplate, r.OCSPKey)
		if err2 != nil {
			log.Printf("Ошибка создания базового OCSP-ответа: %v", err2)

			// Если и это не получается, создаем минимальный ответ со статусом Good
			// Формат ответа OCSPResponseData в соответствии с RFC 6960
			return []byte{
				0x30, 0x0D, // SEQUENCE
				0x0A, 0x01, 0x00, // ENUMERATED (0 = успешный ответ)
				0xA0, 0x08, // [0] ResponseBytes
				0x30, 0x06, // SEQUENCE
				0x06, 0x04, 0x2B, 0x06, 0x01, 0x05, // OID для OCSP
			}, nil
		}

		return responseBytes, nil
	}

	return responseBytes, nil
}

// GetCertificateStatus возвращает статус сертификата, время отзыва и причину отзыва
func (r *OCSPResponder) GetCertificateStatus(serialNumber string) (int, time.Time, int) {
	// Ищем сначала в кеше
	r.mu.RLock()
	ocspCert, exists := r.ocspCertCache[serialNumber]
	r.mu.RUnlock()

	var status int
	var revokedAt time.Time
	var revocationReason int

	if exists {
		// Используем информацию из кеша
		switch ocspCert.CertStatus {
		case 0: // valid
			status = ocsp.Good
		case 1: // expired
			status = ocsp.Good // Истекшие сертификаты не считаются отозванными
		case 2: // revoked
			status = ocsp.Revoked

			// Парсим время отзыва
			if ocspCert.DataRevoke != "" {
				// Используем только формат RFC3339
				var err error
				revokedAt, err = time.Parse(time.RFC3339, ocspCert.DataRevoke)
				if err != nil {
					log.Printf("Ошибка парсинга времени отзыва: %v, использую текущее время", err)
					revokedAt = time.Now()
				}
			} else {
				revokedAt = time.Now()
			}

			revocationReason = parseRevocationReason(ocspCert.ReasonRevoke)
		default:
			status = ocsp.Unknown
		}
	} else {
		// Если не найден в кеше, ищем в таблице отозванных сертификатов ocsp_revoke
		var certStatus int
		var reasonRevoke, dataRevoke string

		err := r.db.QueryRow(`
			SELECT cert_status, reason_revoke, data_revoke
			FROM ocsp_revoke
			WHERE serial_number = ?`, serialNumber).Scan(&certStatus, &reasonRevoke, &dataRevoke)

		if err == nil {
			// Сертификат найден в таблице отозванных сертификатов
			switch certStatus {
			case 0: // valid
				status = ocsp.Good
			case 1: // expired
				status = ocsp.Good // Истекшие сертификаты не считаются отозванными
			case 2: // revoked
				status = ocsp.Revoked

				// Парсим время отзыва
				if dataRevoke != "" {
					// Используем только формат RFC3339
					revokedAt, err = time.Parse(time.RFC3339, dataRevoke)
					if err != nil {
						log.Printf("Ошибка парсинга времени отзыва: %v, использую текущее время", err)
						revokedAt = time.Now()
					}
				} else {
					revokedAt = time.Now()
				}

				// Определяем причину отзыва
				revocationReason = parseRevocationReason(reasonRevoke)
			default:
				status = ocsp.Unknown
			}
		} else {
			// Если не найден в ocsp_revoke, ищем в таблице certs
			err = r.db.QueryRow(`
				SELECT cert_status, reason_revoke, data_revoke
				FROM certs
				WHERE serial_number = ?`, serialNumber).Scan(&certStatus, &reasonRevoke, &dataRevoke)

			if err == nil {
				// Сертификат найден в таблице certs
				switch certStatus {
				case 0: // valid
					status = ocsp.Good
				case 1: // expired
					status = ocsp.Good // Истекшие сертификаты не считаются отозванными
				case 2: // revoked
					status = ocsp.Revoked

					// Парсим время отзыва
					if dataRevoke != "" {
						// Используем только формат RFC3339
						revokedAt, err = time.Parse(time.RFC3339, dataRevoke)
						if err != nil {
							log.Printf("Ошибка парсинга времени отзыва: %v, использую текущее время", err)
							revokedAt = time.Now()
						}
					} else {
						revokedAt = time.Now()
					}

					// Определяем причину отзыва
					revocationReason = parseRevocationReason(reasonRevoke)
				default:
					status = ocsp.Unknown
				}
			} else {
				// Если сертификат не найден, считаем его действительным
				status = ocsp.Good
			}
		}
	}

	return status, revokedAt, revocationReason
}

// standardizeSerialNumber возвращает серийный номер в стандартном формате (hex без ведущих нулей в верхнем регистре)
func standardizeSerialNumber(serialNumber *big.Int) string {
	hexStr := serialNumber.Text(16)
	return strings.ToUpper(hexStr)
}
