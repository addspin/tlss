package crl

import (
	"crypto/rand"
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

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

// StartCRLGeneration запускает периодическую генерацию CRL в отдельной горутине
func StartCRLGeneration(updateInterval time.Duration) {
	ticker := time.NewTicker(updateInterval)
	defer ticker.Stop()

	// Генерируем CRL сразу при запуске
	if err := GenerateCRL(); err != nil {
		log.Printf("Ошибка начальной генерации CRL: %v", err)
	}

	// Запускаем периодическую генерацию
	for range ticker.C {
		if err := GenerateCRL(); err != nil {
			log.Printf("Ошибка генерации CRL: %v", err)
		}
	}
}

// getRevocationReason преобразует текстовую причину отзыва в числовой код
func getRevocationReason(reason string) int {
	switch reason {
	case "keyCompromise":
		return 1 // Компрометация ключа
	case "superseded":
		return 4 // Заменен
	case "unspecified":
		return 0 // Не указана
	default:
		return 0 // Не указана
	}
}

// GenerateCRL генерирует новый CRL, подписанный промежуточным CA
func GenerateCRL() error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		return fmt.Errorf("не удалось подключиться к базе данных: %w", err)
	}
	defer db.Close()

	// Получаем сертификат и ключ промежуточного CA
	var subCA models.SubCA
	err = db.Get(&subCA, "SELECT * FROM sub_ca_tlss WHERE id = 1")
	if err != nil {
		return fmt.Errorf("не удалось получить промежуточный CA: %w", err)
	}

	if subCA.SubCAStatus != 0 {
		return fmt.Errorf("промежуточный CA недействителен")
	}

	// Декодируем сертификат промежуточного CA
	subCACertBlock, _ := pem.Decode([]byte(subCA.PublicKey))
	if subCACertBlock == nil {
		return fmt.Errorf("не удалось декодировать сертификат промежуточного CA")
	}
	subCACert, err := x509.ParseCertificate(subCACertBlock.Bytes)
	if err != nil {
		return fmt.Errorf("не удалось разобрать сертификат промежуточного CA: %w", err)
	}

	// Расшифровываем и декодируем приватный ключ промежуточного CA
	aes := crypts.Aes{}
	decryptedKey, err := aes.Decrypt([]byte(subCA.PrivateKey), crypts.AesSecretKey.Key)
	if err != nil {
		return fmt.Errorf("не удалось расшифровать приватный ключ промежуточного CA: %w", err)
	}

	subCAKeyBlock, _ := pem.Decode(decryptedKey)
	if subCAKeyBlock == nil {
		return fmt.Errorf("не удалось декодировать приватный ключ промежуточного CA")
	}
	subCAKey, err := x509.ParsePKCS1PrivateKey(subCAKeyBlock.Bytes)
	if err != nil {
		return fmt.Errorf("не удалось разобрать приватный ключ промежуточного CA: %w", err)
	}

	// Получаем отозванные сертификаты из базы данных
	var revokedCerts []models.Certs
	err = db.Select(&revokedCerts, `
		SELECT 
			id, cert_status, public_key, 
			data_revoke, reason_revoke, serial_number
		FROM certs 
		WHERE cert_status = 2
	`)
	if err != nil {
		return fmt.Errorf("не удалось получить отозванные сертификаты: %w", err)
	}

	// Создаем записи CRL
	var revokedEntries []pkix.RevokedCertificate
	for _, cert := range revokedCerts {
		// Разбираем время отзыва
		revocationTime, err := time.Parse("02.01.2006 15:04:05", cert.DataRevoke)
		if err != nil {
			continue
		}

		// Преобразуем серийный номер из hex строки в big.Int
		serialNumber := new(big.Int)
		serialNumber.SetString(cert.SerialNumber, 16)

		// Создаем запись отозванного сертификата
		revokedEntry := pkix.RevokedCertificate{
			SerialNumber:   serialNumber,
			RevocationTime: revocationTime,
		}

		// Добавляем причину отзыва
		reason := getRevocationReason(cert.ReasonRevoke)
		revokedEntry.Extensions = []pkix.Extension{
			{
				Id:       []int{2, 5, 29, 21}, // reasonCode
				Critical: false,
				Value:    []byte{byte(reason)},
			},
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
			LastUpdate:         time.Now().Format("02.01.2006 15:04:05"),
			NextUpdate:         time.Now().Add(time.Duration(viper.GetInt("crl.updateInterval")) * time.Hour).Format("02.01.2006 15:04:05"),
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
			return fmt.Errorf("не удалось вставить информацию о CRL: %w", err)
		}
	} else if err != nil {
		return fmt.Errorf("не удалось получить информацию о CRL: %w", err)
	} else {
		// Обновляем существующую информацию о CRL
		crlInfo.LastUpdate = time.Now().Format("02.01.2006 15:04:05")
		crlInfo.NextUpdate = time.Now().Add(time.Duration(viper.GetInt("crl.updateInterval")) * time.Hour).Format("02.01.2006 15:04:05")
		crlInfo.CrlNumber++
		_, err = db.Exec(`
			UPDATE crl_info SET
				last_update = ?,
				next_update = ?,
				crl_number = ?
		`, crlInfo.LastUpdate, crlInfo.NextUpdate, crlInfo.CrlNumber)
		if err != nil {
			return fmt.Errorf("не удалось обновить информацию о CRL: %w", err)
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
		return fmt.Errorf("не удалось создать CRL: %w", err)
	}

	// Сохраняем CRL в файл
	crlPath := "./crlFile/revoked.crl"
	err = saveCRLToFile(crlBytes, crlPath)
	if err != nil {
		return fmt.Errorf("не удалось сохранить CRL: %w", err)
	}

	log.Printf("Успешно сгенерирован CRL с %d отозванными сертификатами", len(revokedEntries))
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
