package crl

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/pem"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"encoding/asn1"
	"strings"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

const crlRootCAPemPath = "./crlFile/rootca.pem"
const crlSubCAPemPath = "./crlFile/subca.pem"
const crlRootCAPath = "./crlFile/rootca.crl"
const crlSubCAPath = "./crlFile/subca.crl"
const crlBundlePath = "./crlFile/bundleca.crl"
const crlBundleCAPemPath = "./crlFile/bundleca.pem"

// StartCombinedCRLGeneration запускает периодическую генерацию CRL для Root CA и Sub CA
func StartCombinedCRLGeneration(updateInterval time.Duration) {
	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()

	// Генерируем CRL сразу при запуске
	if err := CombinedCRL(); err != nil {
		log.Printf("Combined CRL: Ошибка начальной генерации CRL: %v", err)
	}

	// Запускаем периодическую генерацию
	for range ticker.C {
		if err := CombinedCRL(); err != nil {
			log.Printf("Combined CRL: Ошибка генерации CRL: %v", err)
		}
	}
}

// getRevocationReason преобразует текстовую причину отзыва в числовой код CRLReason (RFC 5280)
// 0: unspecified, 1: keyCompromise, 2: cACompromise, 3: affiliationChanged, 4: superseded,
// 5: cessationOfOperation, 6: certificateHold, 8: removeFromCRL, 9: privilegeWithdrawn, 10: aACompromise
func getRevocationReason(reason string) int {
	r := strings.ToLower(strings.TrimSpace(reason))
	switch r {
	case "", "unspecified":
		return 0
	case "keyCompromise":
		return 1
	case "cacompromise":
		return 2
	case "affiliationchanged":
		return 3
	case "superseded":
		return 4
	case "cessationofoperation":
		return 5
	case "certificatehold":
		return 6
	case "removefromcrl":
		return 8
	case "privilegewithdrawn":
		return 9
	case "aacompromise":
		return 10
	default:
		return 0
	}
}

// GenerateSubCACRL генерирует CRL, для серверных и клиентских сертификатов подписанных Sub CA
func GenerateSubCACRL() (crlSubCABytes []byte, err error) {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		return nil, fmt.Errorf("sub CA CRL: не удалось подключиться к базе данных: %w", err)
	}
	defer db.Close()

	// Получаем сертификат и ключ промежуточного CA
	var subCA models.CAData
	err = db.Get(&subCA, "SELECT * FROM ca_certs WHERE type_ca = 'Sub' AND cert_status = 0")
	if err != nil {
		return nil, fmt.Errorf("sub CA CRL: не удалось получить промежуточный CA: %w", err)
	}

	if subCA.CertStatus != 0 {
		return nil, fmt.Errorf("sub CA CRL: промежуточный CA недействителен")
	}

	// Декодируем сертификат промежуточного CA
	subCACertBlock, _ := pem.Decode([]byte(subCA.PublicKey))
	if subCACertBlock == nil {
		return nil, fmt.Errorf("sub CA CRL: не удалось декодировать сертификат промежуточного CA")
	}
	subCACert, err := x509.ParseCertificate(subCACertBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sub CA CRL: не удалось разобрать сертификат промежуточного CA: %w", err)
	}

	// Расшифровываем и декодируем приватный ключ промежуточного CA
	aes := crypts.Aes{}
	decryptedKey, err := aes.Decrypt([]byte(subCA.PrivateKey), crypts.AesSecretKey.Key)
	if err != nil {
		return nil, fmt.Errorf("sub CA CRL: не удалось расшифровать приватный ключ промежуточного CA: %w", err)
	}

	subCAKeyBlock, _ := pem.Decode(decryptedKey)
	if subCAKeyBlock == nil {
		return nil, fmt.Errorf("sub CA CRL: не удалось декодировать приватный ключ промежуточного CA")
	}
	subCAKey, err := x509.ParsePKCS1PrivateKey(subCAKeyBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("sub CA CRL: не удалось разобрать приватный ключ промежуточного CA: %w", err)
	}

	var revokedEntries []pkix.RevokedCertificate

	// Получаем отозванные серверные сертификаты
	var revokedServerCerts []models.CertsData
	err = db.Select(&revokedServerCerts, `
		SELECT 
			id, cert_status, public_key, 
			data_revoke, reason_revoke, serial_number
		FROM certs 
		WHERE cert_status = 2
	`)
	if err != nil {
		return nil, fmt.Errorf("sub CA CRL: предупреждение - не удалось получить отозванные серверные сертификаты: %v", err)
	} else {
		for _, cert := range revokedServerCerts {
			entry, err := createRevokedEntry(cert.SerialNumber, cert.DataRevoke, cert.ReasonRevoke)
			if err != nil {
				return nil, fmt.Errorf("sub CA CRL: ошибка создания записи для серверного сертификата %s: %v", cert.SerialNumber, err)
			}
			revokedEntries = append(revokedEntries, entry)
		}
	}

	// Получаем отозванные клинтские сертификаты
	var revokedUserCerts []models.UserCertsData
	err = db.Select(&revokedUserCerts, `
		SELECT 
			id, cert_status, public_key, 
			data_revoke, reason_revoke, serial_number
		FROM user_certs 
		WHERE cert_status = 2
	`)
	if err != nil {
		return nil, fmt.Errorf("sub CA CRL: предупреждение - не удалось получить отозванные клинтские сертификаты: %v", err)
	} else {
		for _, cert := range revokedUserCerts {
			entry, err := createRevokedEntry(cert.SerialNumber, cert.DataRevoke, cert.ReasonRevoke)
			if err != nil {
				return nil, fmt.Errorf("sub CA CRL: ошибка создания записи для клинтского сертификата %s: %v", cert.SerialNumber, err)
			}
			revokedEntries = append(revokedEntries, entry)
		}
	}

	// Получаем текущую информацию о CRL или создаем новую
	var SubCAcrlInfo models.CRLInfo
	err = db.Get(&SubCAcrlInfo, "SELECT * FROM sub_ca_crl_info LIMIT 1")
	if err == sql.ErrNoRows {
		// Создаем новую информацию о CRL
		SubCAcrlInfo = models.CRLInfo{
			Version:            viper.GetInt("SubCAcrl.version"),
			SignatureAlgorithm: "SHA256-RSA",
			IssuerName:         subCACert.Subject.String(),
			LastUpdate:         time.Now().Format(time.RFC3339),
			NextUpdate:         time.Now().Add(time.Duration(viper.GetInt("SubCAcrl.updateInterval")) * time.Hour).Format(time.RFC3339),
			CrlNumber:          1,
			CrlURL:             viper.GetString("SubCAcrl.crlURL"),
		}
		_, err = db.Exec(`
			INSERT INTO sub_ca_crl_info (
				version, signature_algorithm, issuer_name, last_update, next_update,
				crl_number, authority_key_identifier, crl_url
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, SubCAcrlInfo.Version, SubCAcrlInfo.SignatureAlgorithm, SubCAcrlInfo.IssuerName,
			SubCAcrlInfo.LastUpdate, SubCAcrlInfo.NextUpdate, SubCAcrlInfo.CrlNumber,
			subCACert.SubjectKeyId, SubCAcrlInfo.CrlURL)
		if err != nil {
			return nil, fmt.Errorf("sub CA CRL: не удалось вставить информацию о CRL: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("sub CA CRL: не удалось получить информацию о CRL: %w", err)
	} else {
		// Обновляем существующую информацию о CRL
		SubCAcrlInfo.LastUpdate = time.Now().Format(time.RFC3339)
		SubCAcrlInfo.NextUpdate = time.Now().Add(time.Duration(viper.GetInt("SubCAcrl.updateInterval")) * time.Hour).Format(time.RFC3339)
		SubCAcrlInfo.CrlNumber++
		_, err = db.Exec(`
			UPDATE sub_ca_crl_info SET
				last_update = ?,
				next_update = ?,
				crl_number = ?
		`, SubCAcrlInfo.LastUpdate, SubCAcrlInfo.NextUpdate, SubCAcrlInfo.CrlNumber)
		if err != nil {
			return nil, fmt.Errorf("sub CA CRL: не удалось обновить информацию о CRL: %w", err)
		}
	}

	// Создаем шаблон CRL
	template := &x509.RevocationList{
		SignatureAlgorithm:  x509.SHA256WithRSA,
		RevokedCertificates: revokedEntries,
		Number:              big.NewInt(int64(SubCAcrlInfo.CrlNumber)),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(time.Duration(viper.GetInt("SubCAcrl.updateInterval")) * time.Hour),
	}

	// Генерируем CRL в DER формате
	crlSubCABytes, err = x509.CreateRevocationList(rand.Reader, template, subCACert, subCAKey)
	if err != nil {
		return nil, fmt.Errorf("sub CA CRL: не удалось создать CRL: %w", err)
	}

	log.Printf("sub CA CRL: Успешно сгенерирован CRL с %d отозванными сертификатами", len(revokedEntries))
	return crlSubCABytes, nil
}

// createRevokedEntry создает запись отозванного сертификата для CRL
func createRevokedEntry(serialNumber, dataRevoke, reasonRevoke string) (pkix.RevokedCertificate, error) {
	// Парсим время отзыва
	var revocationTime time.Time
	var err error
	if dataRevoke != "" {
		// Используем только формат RFC3339
		revocationTime, err = time.Parse(time.RFC3339, dataRevoke)
		if err != nil {
			log.Printf("combined CRL: Ошибка парсинга времени отзыва: %v, использую текущее время", err)
			revocationTime = time.Now()
		}
	} else {
		revocationTime = time.Now()
	}

	// Преобразуем серийный номер из hex строки в big.Int
	serialBig := new(big.Int)
	serialBig.SetString(serialNumber, 16)

	// Создаем запись отозванного сертификата
	revokedEntry := pkix.RevokedCertificate{
		SerialNumber:   serialBig,
		RevocationTime: revocationTime,
	}

	// Добавляем причину отзыва (DER-кодированная ASN.1 ENUMERATED)
	reason := getRevocationReason(reasonRevoke)
	if reason != 0 { // unspecified обычно опускают
		val, err := asn1.Marshal(asn1.Enumerated(reason))
		if err != nil {
			return revokedEntry, fmt.Errorf("marshal reasonCode: %w", err)
		}
		revokedEntry.Extensions = append(revokedEntry.Extensions, pkix.Extension{
			Id:       []int{2, 5, 29, 21}, // reasonCode
			Critical: false,
			Value:    val,
		})
	}

	return revokedEntry, nil
}

// GenerateCRL генерирует новый CRL, подписанный промежуточным CA (оригинальная функция)
func GenerateCRL() error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		return fmt.Errorf("server CRL: не удалось подключиться к базе данных: %w", err)
	}
	defer db.Close()

	// Получаем сертификат и ключ промежуточного CA
	var subCA models.CAData
	err = db.Get(&subCA, "SELECT * FROM ca_certs WHERE type_ca = 'Sub' AND cert_status = 0")
	if err != nil {
		return fmt.Errorf("server CRL: не удалось получить промежуточный CA: %w", err)
	}

	if subCA.CertStatus != 0 {
		return fmt.Errorf("server CRL: промежуточный CA недействителен")
	}

	// Декодируем сертификат промежуточного CA
	subCACertBlock, _ := pem.Decode([]byte(subCA.PublicKey))
	if subCACertBlock == nil {
		return fmt.Errorf("server CRL: не удалось декодировать сертификат промежуточного CA")
	}
	subCACert, err := x509.ParseCertificate(subCACertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("server CRL: не удалось разобрать сертификат промежуточного CA: %w", err)
	}

	// Расшифровываем и декодируем приватный ключ промежуточного CA
	aes := crypts.Aes{}
	decryptedKey, err := aes.Decrypt([]byte(subCA.PrivateKey), crypts.AesSecretKey.Key)
	if err != nil {
		return fmt.Errorf("server CRL: не удалось расшифровать приватный ключ промежуточного CA: %w", err)
	}

	subCAKeyBlock, _ := pem.Decode(decryptedKey)
	if subCAKeyBlock == nil {
		return fmt.Errorf("server CRL: не удалось декодировать приватный ключ промежуточного CA")
	}
	subCAKey, err := x509.ParsePKCS1PrivateKey(subCAKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("server CRL: не удалось разобрать приватный ключ промежуточного CA: %w", err)
	}

	// Получаем отозванные серверные сертификаты из базы данных
	var revokedCerts []models.CertsData
	err = db.Select(&revokedCerts, `
		SELECT 
			id, cert_status, public_key, 
			data_revoke, reason_revoke, serial_number
		FROM certs 
		WHERE cert_status = 2
	`)
	if err != nil {
		return fmt.Errorf("server CRL: не удалось получить отозванные сертификаты: %w", err)
	}

	// Создаем записи CRL
	var revokedEntries []pkix.RevokedCertificate
	for _, cert := range revokedCerts {
		// Парсим время отзыва
		var revocationTime time.Time
		if cert.DataRevoke != "" {
			// Используем только формат RFC3339
			revocationTime, err = time.Parse(time.RFC3339, cert.DataRevoke)
			if err != nil {
				log.Printf("server CRL: Ошибка парсинга времени отзыва: %v, использую текущее время", err)
				revocationTime = time.Now()
			}
		} else {
			revocationTime = time.Now()
		}

		// Преобразуем серийный номер из hex строки в big.Int
		serialNumber := new(big.Int)
		serialNumber.SetString(cert.SerialNumber, 16)

		// Создаем запись отозванного сертификата
		revokedEntry := pkix.RevokedCertificate{
			SerialNumber:   serialNumber,
			RevocationTime: revocationTime,
		}

		// Добавляем причину отзыва (DER-кодированная ASN.1 ENUMERATED)
		reason := getRevocationReason(cert.ReasonRevoke)
		if reason != 0 { // unspecified обычно опускают
			val, err := asn1.Marshal(asn1.Enumerated(reason))
			if err != nil {
				return fmt.Errorf("server crl: marshal reasonCode: %w", err)
			}
			revokedEntry.Extensions = append(revokedEntry.Extensions, pkix.Extension{
				Id:       []int{2, 5, 29, 21}, // reasonCode
				Critical: false,
				Value:    val,
			})
		}

		revokedEntries = append(revokedEntries, revokedEntry)
	}

	// Получаем текущую информацию о CRL или создаем новую
	var crlInfo models.CRLInfo
	err = db.Get(&crlInfo, "SELECT * FROM crl_info LIMIT 1")
	if err == sql.ErrNoRows {
		// Создаем новую информацию о CRL
		crlInfo = models.CRLInfo{
			Version:            viper.GetInt("crl.version"),
			SignatureAlgorithm: "SHA256-RSA",
			IssuerName:         subCACert.Subject.String(),
			LastUpdate:         time.Now().Format(time.RFC3339),
			NextUpdate:         time.Now().Add(time.Duration(viper.GetInt("crl.updateInterval")) * time.Hour).Format(time.RFC3339),
			CrlNumber:          1,
			CrlURL:             viper.GetString("crl.crlURL"),
		}
		_, err = db.Exec(`
			INSERT INTO crl_info (
				version, signature_algorithm, issuer_name, last_update, next_update,
				crl_number, authority_key_identifier, crl_url
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, crlInfo.Version, crlInfo.SignatureAlgorithm, crlInfo.IssuerName,
			crlInfo.LastUpdate, crlInfo.NextUpdate, crlInfo.CrlNumber,
			subCACert.SubjectKeyId, crlInfo.CrlURL)
		if err != nil {
			return fmt.Errorf("server CRL: не удалось вставить информацию о CRL: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("server CRL: не удалось получить информацию о CRL: %w", err)
	} else {
		// Обновляем существующую информацию о CRL
		crlInfo.LastUpdate = time.Now().Format(time.RFC3339)
		crlInfo.NextUpdate = time.Now().Add(time.Duration(viper.GetInt("crl.updateInterval")) * time.Hour).Format(time.RFC3339)
		crlInfo.CrlNumber++
		_, err = db.Exec(`
			UPDATE crl_info SET
				last_update = ?,
				next_update = ?,
				crl_number = ?
		`, crlInfo.LastUpdate, crlInfo.NextUpdate, crlInfo.CrlNumber)
		if err != nil {
			return fmt.Errorf("server CRL: не удалось обновить информацию о CRL: %w", err)
		}
	}

	// Создаем шаблон CRL
	template := &x509.RevocationList{
		SignatureAlgorithm:  x509.SHA256WithRSA,
		RevokedCertificates: revokedEntries,
		Number:              big.NewInt(int64(crlInfo.CrlNumber)),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(time.Duration(viper.GetInt("crl.updateInterval")) * time.Hour),
	}

	// Генерируем CRL
	crlBytes, err := x509.CreateRevocationList(rand.Reader, template, subCACert, subCAKey)
	if err != nil {
		return fmt.Errorf("server CRL: не удалось создать CRL: %w", err)
	}

	// Сохраняем CRL в файл
	crlPath := "./crlFile/revoked.crl"
	err = saveCRLToFile(crlBytes, crlPath)
	if err != nil {
		return fmt.Errorf("server CRL: не удалось сохранить CRL: %w", err)
	}

	log.Printf("Server CRL: Успешно сгенерирован CRL с %d отозванными сертификатами", len(revokedEntries))
	return nil
}

// GenerateRootCACRL генерирует CRL для отозванных Sub CA сертификатов, подписанный Root CA
func GenerateRootCACRL() (crlRootBytes []byte, err error) {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		return nil, fmt.Errorf("root CA CRL: не удалось подключиться к базе данных: %w", err)
	}
	defer db.Close()

	var rootCert *x509.Certificate
	var rootKey *rsa.PrivateKey

	// Сначала пытаемся загрузить Root CA из базы данных
	var rootCA models.CAData
	err = db.Get(&rootCA, "SELECT * FROM ca_certs WHERE type_ca = 'Root' AND cert_status = 0")
	if err == nil && rootCA.CertStatus == 0 {
		// Загружаем Root CA из базы данных
		rootCertBlock, _ := pem.Decode([]byte(rootCA.PublicKey))
		if rootCertBlock == nil {
			return nil, fmt.Errorf("root CA CRL: failed to decode root CA certificate PEM from database")
		}
		rootCert, err = x509.ParseCertificate(rootCertBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("root CA CRL: failed to parse root CA certificate from database: %w", err)
		}

		// Расшифровываем приватный ключ Root CA
		aes := crypts.Aes{}
		decryptedKey, err := aes.Decrypt([]byte(rootCA.PrivateKey), crypts.AesSecretKey.Key)
		if err != nil {
			return nil, fmt.Errorf("root CA CRL: failed to decrypt root CA private key: %w", err)
		}

		rootKeyBlock, _ := pem.Decode(decryptedKey)
		if rootKeyBlock == nil {
			return nil, fmt.Errorf("root CA CRL: failed to decode root CA private key PEM from database")
		}
		rootKey, err = x509.ParsePKCS1PrivateKey(rootKeyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("root CA CRL: failed to parse root CA private key from database: %w", err)
		}
	} else {
		// Fallback: загружаем Root CA из файлов
		rootCertPath := viper.GetString("ca_tlss.path_cert")
		rootKeyPath := viper.GetString("ca_tlss.path_key")
		if rootCertPath == "" || rootKeyPath == "" {
			return nil, fmt.Errorf("root CA CRL: Root CA не найден в базе данных и в конфигурации не заданы ca_tlss.path_cert/ca_tlss.path_key")
		}

		rootCertData, err := os.ReadFile(rootCertPath)
		if err != nil {
			return nil, fmt.Errorf("root CA CRL: failed to read root CA certificate from file: %w", err)
		}
		rootKeyData, err := os.ReadFile(rootKeyPath)
		if err != nil {
			return nil, fmt.Errorf("root CA CRL: failed to read root CA private key from file: %w", err)
		}
		rootCertBlock, _ := pem.Decode(rootCertData)
		if rootCertBlock == nil {
			return nil, fmt.Errorf("root CA CRL: failed to decode root CA certificate PEM from file")
		}
		rootCert, err = x509.ParseCertificate(rootCertBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("root CA CRL: failed to parse root CA certificate from file: %w", err)
		}
		rootKeyBlock, _ := pem.Decode(rootKeyData)
		if rootKeyBlock == nil {
			return nil, fmt.Errorf("root CA CRL: failed to decode root CA private key PEM from file")
		}
		rootKey, err = x509.ParsePKCS1PrivateKey(rootKeyBlock.Bytes)
		if err != nil {
			return nil, fmt.Errorf("root CA CRL: failed to parse root CA private key from file: %w", err)
		}
	}

	var revokedEntries []pkix.RevokedCertificate

	// Получаем отозванные Sub CA сертификаты
	var revokedSubCACerts []models.CAData
	err = db.Select(&revokedSubCACerts, `
		SELECT 
			id, cert_status, public_key, 
			data_revoke, reason_revoke, serial_number
		FROM ca_certs 
		WHERE type_ca = 'Sub' AND cert_status = 2
	`)
	if err != nil {
		return nil, fmt.Errorf("root CA CRL: предупреждение - не удалось получить отозванные Sub CA сертификаты: %v", err)
	} else {
		for _, cert := range revokedSubCACerts {
			entry, err := createRevokedEntry(cert.SerialNumber, cert.DataRevoke, cert.ReasonRevoke)
			if err != nil {
				log.Printf("root CA CRL: ошибка создания записи для Sub CA сертификата %s: %v", cert.SerialNumber, err)
				return nil, fmt.Errorf("root CA CRL: ошибка создания записи для Sub CA сертификата %s: %v", cert.SerialNumber, err)
			}
			revokedEntries = append(revokedEntries, entry)
		}
	}

	// Получаем текущую информацию о Root CA CRL или создаем новую
	var rootCACrlInfo models.CRLInfo
	err = db.Get(&rootCACrlInfo, "SELECT * FROM root_ca_crl_info LIMIT 1")
	if err == sql.ErrNoRows {
		// Создаем новую информацию о Root CA CRL
		rootCACrlInfo = models.CRLInfo{
			Version:            viper.GetInt("RootCAcrl.version"),
			SignatureAlgorithm: "SHA256-RSA",
			IssuerName:         rootCert.Subject.String(),
			LastUpdate:         time.Now().Format(time.RFC3339),
			NextUpdate:         time.Now().Add(time.Duration(viper.GetInt("RootCAcrl.updateInterval")) * time.Hour).Format(time.RFC3339),
			CrlNumber:          1,
			CrlURL:             viper.GetString("RootCAcrl.crlURL"),
		}
		_, err = db.Exec(`
			INSERT INTO root_ca_crl_info (
				version, signature_algorithm, issuer_name, last_update, next_update,
				crl_number, authority_key_identifier, crl_url
			) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		`, rootCACrlInfo.Version, rootCACrlInfo.SignatureAlgorithm, rootCACrlInfo.IssuerName,
			rootCACrlInfo.LastUpdate, rootCACrlInfo.NextUpdate, rootCACrlInfo.CrlNumber,
			rootCert.SubjectKeyId, rootCACrlInfo.CrlURL)
		if err != nil {
			return nil, fmt.Errorf("root CA CRL: не удалось вставить информацию о CRL: %w", err)
		}
	} else if err != nil {
		return nil, fmt.Errorf("root CA CRL: не удалось получить информацию о CRL: %w", err)
	} else {
		// Обновляем существующую информацию о Root CA CRL
		rootCACrlInfo.LastUpdate = time.Now().Format(time.RFC3339)
		rootCACrlInfo.NextUpdate = time.Now().Add(time.Duration(viper.GetInt("RootCAcrl.updateInterval")) * time.Hour).Format(time.RFC3339)
		rootCACrlInfo.CrlNumber++
		_, err = db.Exec(`
			UPDATE root_ca_crl_info SET
				last_update = ?,
				next_update = ?,
				crl_number = ?
		`, rootCACrlInfo.LastUpdate, rootCACrlInfo.NextUpdate, rootCACrlInfo.CrlNumber)
		if err != nil {
			return nil, fmt.Errorf("root CA CRL: не удалось обновить информацию о CRL: %w", err)
		}
	}

	// Создаем шаблон CRL
	template := &x509.RevocationList{
		SignatureAlgorithm:  x509.SHA256WithRSA,
		RevokedCertificates: revokedEntries,
		Number:              big.NewInt(int64(rootCACrlInfo.CrlNumber)),
		ThisUpdate:          time.Now(),
		NextUpdate:          time.Now().Add(time.Duration(viper.GetInt("RootCAcrl.updateInterval")) * time.Hour),
	}
	// Генерируем CRL в DER формате
	crlRootBytes, err = x509.CreateRevocationList(rand.Reader, template, rootCert, rootKey)
	if err != nil {
		return nil, fmt.Errorf("root CA CRL: не удалось создать CRL: %w", err)
	}

	log.Printf("Root CA CRL: Успешно сгенерирован с %d отозванными Sub CA сертификатами", len(revokedEntries))
	return crlRootBytes, nil
}

// CombinedCRL генерирует CRL для Root CA и Sub CA, сохраняет их отдельно и создает бандл rootca.pem и subca.pem
func CombinedCRL() error {
	var err error

	// Генерируем Sub CA CRL
	subCABytes, err := GenerateSubCACRL()
	if err != nil {
		return fmt.Errorf("combined CRL: не удалось сгенерировать Sub CA CRL: %w", err)
	}

	// Генерируем Root CA CRL
	rootCABytes, err := GenerateRootCACRL()
	if err != nil {
		return fmt.Errorf("combined CRL: не удалось сгенерировать Root CA CRL: %w", err)
	}

	// Сохраняем Sub CA CRL в DER формате
	err = saveCRLToFile(subCABytes, crlSubCAPath)
	if err != nil {
		return fmt.Errorf("combined CRL: не удалось сохранить Sub CA CRL в DER формате: %w", err)
	}

	// Сохраняем Sub CA CRL в PEM формате
	subCAPem := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: subCABytes,
	})
	if subCAPem == nil {
		return fmt.Errorf("combined CRL: не удалось конвертировать Sub CA CRL в PEM формат")
	}
	err = os.WriteFile(crlSubCAPemPath, subCAPem, 0644)
	if err != nil {
		return fmt.Errorf("combined CRL: не удалось сохранить Sub CA CRL в PEM формате: %w", err)
	}

	// Сохраняем Root CA CRL в DER формате
	err = saveCRLToFile(rootCABytes, crlRootCAPath)
	if err != nil {
		return fmt.Errorf("combined CRL: не удалось сохранить Root CA CRL в DER формате: %w", err)
	}

	// Сохраняем Root CA CRL в PEM формате
	rootCAPem := pem.EncodeToMemory(&pem.Block{
		Type:  "X509 CRL",
		Bytes: rootCABytes,
	})
	if rootCAPem == nil {
		return fmt.Errorf("combined CRL: не удалось конвертировать Root CA CRL в PEM формат")
	}
	err = os.WriteFile(crlRootCAPemPath, rootCAPem, 0644)
	if err != nil {
		return fmt.Errorf("combined CRL: не удалось сохранить Root CA CRL в PEM формате: %w", err)
	}

	// Создаем и сохраняем бандл из Root CA и Sub CA CRL
	bundle := []byte{}
	bundle = append(bundle, rootCABytes...)
	bundle = append(bundle, subCABytes...)

	bundlePem := []byte{}
	bundlePem = append(bundlePem, rootCAPem...)
	bundlePem = append(bundlePem, subCAPem...)

	err = os.WriteFile(crlBundleCAPemPath, bundlePem, 0644)
	if err != nil {
		return fmt.Errorf("combined CRL: не удалось сохранить бандл CRL в PEM формате: %w", err)
	}

	err = os.WriteFile(crlBundlePath, bundle, 0644)
	if err != nil {
		return fmt.Errorf("combined CRL: не удалось сохранить бандл CRL: %w", err)
	}

	log.Printf("Combined CRL: Успешно сгенерированы и сохранены Root CA и Sub CA CRL с бандлом")
	return nil
}

// saveCRLToFile сохраняет CRL в файл
func saveCRLToFile(crlBytes []byte, path string) error {
	// Создаем директорию, если она не существует
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	// Сохраняем CRL в файл
	crlFile, err := os.Create(path)
	if err != nil {
		return err
	}
	defer crlFile.Close()

	_, err = crlFile.Write(crlBytes)
	return err
}
