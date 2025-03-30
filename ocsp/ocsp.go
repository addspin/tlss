package ocsp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
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
	if err := responder.GenerateOCSPCertificate(); err != nil {
		log.Printf("Ошибка создания OCSP-сертификата: %v", err)
	}

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
func (r *OCSPResponder) GenerateOCSPCertificate() error {
	log.Println("Проверка и создание OCSP-сертификата...")

	// Проверяем наличие действующего OCSP-сертификата в базе
	var exists bool
	err := r.db.Get(&exists, "SELECT EXISTS(SELECT 1 FROM ocsp_cert WHERE cert_status = 0 AND ocsp_signing_eku = true LIMIT 1)")
	if err != nil {
		return fmt.Errorf("ошибка проверки наличия OCSP-сертификата: %v", err)
	}

	// Если действующий OCSP-сертификат есть, загрузим его
	if exists {
		var ocspCert models.OCSPCertificate
		err = r.db.Get(&ocspCert, "SELECT * FROM ocsp_cert WHERE cert_status = 0 AND ocsp_signing_eku = true LIMIT 1")
		if err != nil {
			return fmt.Errorf("не удалось загрузить существующий OCSP-сертификат: %v", err)
		}

		// Декодируем публичный ключ OCSP-сертификата
		certBlock, _ := pem.Decode([]byte(ocspCert.PublicKey))
		if certBlock == nil {
			return fmt.Errorf("не удалось декодировать публичный ключ OCSP-сертификата")
		}

		r.OCSPCert, err = x509.ParseCertificate(certBlock.Bytes)
		if err != nil {
			return fmt.Errorf("не удалось разобрать OCSP-сертификат: %v", err)
		}

		// Расшифровываем и декодируем приватный ключ OCSP-сертификата
		aes := crypts.Aes{}
		decryptedKey, err := aes.Decrypt([]byte(ocspCert.PrivateKey), crypts.AesSecretKey.Key)
		if err != nil {
			return fmt.Errorf("не удалось расшифровать приватный ключ OCSP-сертификата: %v", err)
		}

		keyBlock, _ := pem.Decode(decryptedKey)
		if keyBlock == nil {
			return fmt.Errorf("не удалось декодировать приватный ключ OCSP-сертификата")
		}

		r.OCSPKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return fmt.Errorf("не удалось разобрать приватный ключ OCSP-сертификата: %v", err)
		}

		log.Println("Существующий OCSP-сертификат успешно загружен")
		return nil
	}

	// Создаем новый OCSP-сертификат
	log.Println("Создание нового OCSP-сертификата...")

	// Генерируем новую RSA ключевую пару для OCSP-сертификата
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать RSA ключевую пару: %v", err)
	}
	r.OCSPKey = privateKey

	// Генерируем случайный серийный номер
	serialNumber, err := rand.Int(rand.Reader, big.NewInt(1).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("не удалось сгенерировать серийный номер: %v", err)
	}

	// Получаем настройки из конфигурации для OCSP-сертификата
	now := time.Now()
	// OCSP-сертификаты обычно имеют меньший срок действия, чем CA-сертификаты
	// Используем 30% от срока действия промежуточного CA, но не более 90 дней
	ttl := int(time.Until(r.SubCACert.NotAfter).Hours() / 24 * 0.3)
	if ttl > 90 {
		ttl = 90 // Максимум 90 дней
	}
	expiry := now.AddDate(0, 0, ttl)

	// Формируем шаблон OCSP-сертификата
	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:         "TLSS OCSP Responder",
			Country:            []string{r.SubCACert.Subject.Country[0]},
			Province:           []string{r.SubCACert.Subject.Province[0]},
			Locality:           []string{r.SubCACert.Subject.Locality[0]},
			Organization:       []string{r.SubCACert.Subject.Organization[0]},
			OrganizationalUnit: []string{r.SubCACert.Subject.OrganizationalUnit[0]},
		},
		NotBefore:             now,
		NotAfter:              expiry,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageOCSPSigning},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	// Добавляем расширение id-pkix-ocsp-nocheck (OID: 1.3.6.1.5.5.7.48.1.5)
	ocspNoCheckExt := pkix.Extension{
		Id:       []int{1, 3, 6, 1, 5, 5, 7, 48, 1, 5},
		Critical: false,
		Value:    []byte{0x05, 0x00}, // DER-кодирование NULL
	}
	template.ExtraExtensions = append(template.ExtraExtensions, ocspNoCheckExt)

	// Создаем сертификат, подписанный промежуточным CA
	certDER, err := x509.CreateCertificate(rand.Reader, template, r.SubCACert, &privateKey.PublicKey, r.SubCAKey)
	if err != nil {
		return fmt.Errorf("не удалось создать OCSP-сертификат: %v", err)
	}

	// Конвертируем сертификат и ключ в PEM-формат
	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})

	keyPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
	})

	// Шифруем приватный ключ
	aes := crypts.Aes{}
	encryptedKey, err := aes.Encrypt(keyPEM, crypts.AesSecretKey.Key)
	if err != nil {
		return fmt.Errorf("не удалось зашифровать приватный ключ OCSP-сертификата: %v", err)
	}

	// Парсим созданный сертификат
	r.OCSPCert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return fmt.Errorf("не удалось разобрать созданный OCSP-сертификат: %v", err)
	}

	// Вычисляем хеши для имени и ключа издателя
	issuerNameHash, issuerKeyHash, hashAlgo := calculateIssuerHashes(r.SubCACert)

	// Сохраняем OCSP-сертификат в базу данных
	_, err = r.db.Exec(`
		INSERT INTO ocsp_cert (
			create_time, serial_number, domain, issuer_name, public_key, private_key,
			cert_status, cert_create_time, cert_expire_time,
			ocsp_signing_eku, ocsp_nocheck, issuer_subca_serial_number,
			issuer_name_hash, issuer_key_hash, hash_algorithm
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
	`,
		now.Format(time.RFC3339),
		fmt.Sprintf("%X", serialNumber),
		"ocsp.responder", // Доменное имя для OCSP-сертификата
		r.SubCACert.Subject.String(),
		string(certPEM),
		string(encryptedKey),
		0, // valid
		now.Format("02.01.2006 15:04:05"),
		expiry.Format("02.01.2006 15:04:05"),
		true,
		true,
		r.SubCACert.SerialNumber.String(),
		issuerNameHash,
		issuerKeyHash,
		hashAlgo,
	)
	if err != nil {
		return fmt.Errorf("не удалось сохранить OCSP-сертификат в базу данных: %v", err)
	}

	log.Println("Новый OCSP-сертификат успешно создан и сохранен")
	return nil
}

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
	var certs []models.Certs
	err := r.db.Select(&certs, `
		SELECT 
			id, serial_number, domain, cert_status, reason_revoke, data_revoke,
			cert_create_time, cert_expire_time
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

	// Создаем кеш для быстрого доступа
	newCache := make(map[string]*models.OCSPCertificate)

	// Обрабатываем каждый отозванный сертификат
	for _, cert := range certs {
		// Создаем запись OCSP
		ocspCert := &models.OCSPCertificate{
			SerialNumber:            cert.SerialNumber,
			Domain:                  cert.Domain,
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

		// Проверяем, существует ли уже запись для этого сертификата
		var existingId int
		err = r.db.QueryRow(`
			SELECT id FROM ocsp_cert 
			WHERE serial_number = ?`, cert.SerialNumber).Scan(&existingId)

		if err == nil {
			// Если запись существует, обновляем её
			_, err = r.db.Exec(`
				UPDATE ocsp_cert SET
					domain = ?, cert_status = ?, reason_revoke = ?, data_revoke = ?,
					ocsp_signing_eku = false, ocsp_nocheck = false,
					this_update = ?, next_update = ?
				WHERE id = ?`,
				ocspCert.Domain, ocspCert.CertStatus, ocspCert.ReasonRevoke, ocspCert.DataRevoke,
				ocspCert.ThisUpdate, ocspCert.NextUpdate, existingId,
			)
			if err != nil {
				log.Printf("Ошибка обновления OCSP-данных для сертификата %s (%s): %v", cert.SerialNumber, cert.Domain, err)
				continue
			}
			log.Printf("Обновлена запись OCSP для сертификата %s (%s)", cert.SerialNumber, cert.Domain)
		} else {
			// Если записи нет, вставляем новую
			_, err = r.db.Exec(`
				INSERT INTO ocsp_cert (
					create_time, serial_number, domain, issuer_name,
					cert_status, reason_revoke, data_revoke,
					cert_create_time, cert_expire_time,
					ocsp_signing_eku, ocsp_nocheck,
					issuer_subca_serial_number, issuer_name_hash, issuer_key_hash, hash_algorithm,
					this_update, next_update
				) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				nowStr, ocspCert.SerialNumber, ocspCert.Domain, ocspCert.IssuerName,
				ocspCert.CertStatus, ocspCert.ReasonRevoke, ocspCert.DataRevoke,
				ocspCert.CertCreateTime, ocspCert.CertExpireTime,
				false, false, // ocsp_signing_eku и ocsp_nocheck должны быть false для отозванных сертификатов
				ocspCert.IssuerSubCASerialNumber, ocspCert.IssuerNameHash, ocspCert.IssuerKeyHash, ocspCert.HashAlgorithm,
				ocspCert.ThisUpdate, ocspCert.NextUpdate,
			)
			if err != nil {
				log.Printf("Ошибка вставки OCSP-данных для сертификата %s (%s): %v", cert.SerialNumber, cert.Domain, err)
				continue
			}
			log.Printf("Добавлена новая запись OCSP для сертификата %s (%s)", cert.SerialNumber, cert.Domain)
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
	// Хешируем имя издателя
	nameHash := sha256.Sum256(issuerCert.RawSubject)

	// Хешируем ключ издателя
	keyHash := sha256.Sum256(issuerCert.RawSubjectPublicKeyInfo)

	return hex.EncodeToString(nameHash[:]), hex.EncodeToString(keyHash[:]), "SHA256"
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

	// Создаем и подписываем OCSP-ответ
	return ocsp.CreateResponse(r.SubCACert, r.OCSPCert, template, r.OCSPKey)
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
				revokedAt, _ = time.Parse("02.01.2006 15:04:05", ocspCert.DataRevoke)
			} else {
				revokedAt = time.Now()
			}

			revocationReason = parseRevocationReason(ocspCert.ReasonRevoke)
		default:
			status = ocsp.Unknown
		}
	} else {
		// Если не найден в кеше, ищем в базе данных
		var certStatus int
		var reasonRevoke, dataRevoke string

		err := r.db.QueryRow(`
			SELECT cert_status, reason_revoke, data_revoke
			FROM certs
			WHERE serial_number = ?`, serialNumber).Scan(&certStatus, &reasonRevoke, &dataRevoke)

		if err == nil {
			// Сертификат найден в базе данных
			switch certStatus {
			case 0: // valid
				status = ocsp.Good
			case 1: // expired
				status = ocsp.Good // Истекшие сертификаты не считаются отозванными
			case 2: // revoked
				status = ocsp.Revoked

				// Парсим время отзыва
				if dataRevoke != "" {
					revokedAt, err = time.Parse("02.01.2006 15:04:05", dataRevoke)
					if err != nil {
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

	return status, revokedAt, revocationReason
}
