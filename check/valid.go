package check

import (
	"log/slog"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

// calculateDaysLeft вычисляет количество оставшихся дней до истечения сертификата
func calculateDaysLeft(expireTime time.Time) int {
	currentTime := time.Now()
	duration := expireTime.Sub(currentTime)
	days := int(duration.Hours() / 24)

	// Если сертификат уже истёк, возвращаем отрицательное значение
	if days < 0 {
		return days
	}

	return days
}

func CheckValidCerts(checkValidationTime time.Duration) {
	slog.Info("CheckValidCerts: Starting certificate validation module")

	// Выполняем проверку сразу при запуске функции
	checkCerts()

	// Затем настраиваем тикер для периодических проверок
	ticker := time.NewTicker(checkValidationTime)
	defer ticker.Stop()

	for range ticker.C {
		checkCerts()
	}
}

func checkCerts() {
	slog.Info("CheckValidCerts: Certificate validation check started")

	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("CheckValidCerts: Database connection error", "error", err)
		return
	}
	defer db.Close()

	// Получаем все сертификаты (включая истёкшие) для обновления days_left
	certificates := []models.CertsData{}
	err = db.Select(&certificates, `SELECT id, domain, cert_create_time, cert_expire_time, cert_status FROM certs WHERE cert_status IN (0, 1)`)
	if err != nil {
		slog.Error("CheckValidCerts: Server certificate query error", "error", err)
		return
	}

	userCertificates := []models.UserCertsData{}
	err = db.Select(&userCertificates, "SELECT id, common_name, cert_create_time, cert_expire_time, cert_status FROM user_certs WHERE cert_status IN (0, 1)")
	if err != nil {
		slog.Error("CheckValidCerts: Client certificate query error", "error", err)
		return
	}

	caCertificates := []models.CAData{}
	err = db.Select(&caCertificates, "SELECT id, common_name, cert_create_time, cert_expire_time, cert_status FROM ca_certs WHERE cert_status IN (0, 1)")
	if err != nil {
		slog.Error("CheckValidCerts: CA certificate query error", "error", err)
		return
	}

	extCACertificates := []models.CAExtData{}
	err = db.Select(&extCACertificates, "SELECT id, common_name, cert_create_time, cert_expire_time, cert_status FROM ca_certs_ext WHERE cert_status IN (0, 1)")
	if err != nil {
		slog.Error("CheckValidCerts: External CA certificate query error", "error", err)
	}

	slog.Info("CheckValidCerts: Found active certificates to check", "server_certs", len(certificates), "user_certs", len(userCertificates), "ca_certs", len(caCertificates), "ext_ca_certs", len(extCACertificates), "total", len(certificates)+len(userCertificates)+len(caCertificates)+len(extCACertificates))

	// Текущее время для сравнения
	currentTime := time.Now()
	// slog.Info("CheckValidCerts: Current time", "time", currentTime.Format(time.RFC3339))

	expiredCount := 0

	// Обновляем days_left у CA сертификатов; cert_status меняем только с 0 → 1
	for _, cert := range caCertificates {
		expireTime, err := time.Parse(time.RFC3339, cert.CertExpireTime)
		if err != nil {
			slog.Error("CheckValidCerts: Expiration time parsing error for certificate", "common_name", cert.CommonName, "id", cert.Id, "error", err)
			continue
		}

		daysLeft := calculateDaysLeft(expireTime)

		_, err = db.Exec("UPDATE ca_certs SET days_left = ? WHERE id = ?", daysLeft, cert.Id)
		if err != nil {
			slog.Error("CheckValidCerts: Error updating days_left for certificate", "common_name", cert.CommonName, "id", cert.Id, "error", err)
		}

		if currentTime.After(expireTime) && cert.CertStatus == 0 {
			_, err := db.Exec("UPDATE ca_certs SET cert_status = 1 WHERE id = ?", cert.Id)
			if err != nil {
				slog.Error("CheckValidCerts: Error updating certificate status", "common_name", cert.CommonName, "id", cert.Id, "error", err)
			} else {
				slog.Warn("CheckValidCerts: Certificate expired and marked as invalid", "common_name", cert.CommonName, "id", cert.Id)
				expiredCount++
			}
		}
	}

	// Обновляем days_left у серверных сертификатов; cert_status меняем только с 0 → 1
	for _, cert := range certificates {
		expireTime, err := time.Parse(time.RFC3339, cert.CertExpireTime)
		if err != nil {
			slog.Error("CheckValidCerts: Expiration time parsing error for certificate", "domain", cert.Domain, "id", cert.Id, "error", err)
			continue
		}

		daysLeft := calculateDaysLeft(expireTime)

		_, err = db.Exec("UPDATE certs SET days_left = ? WHERE id = ?", daysLeft, cert.Id)
		if err != nil {
			slog.Error("CheckValidCerts: Error updating days_left for certificate", "domain", cert.Domain, "id", cert.Id, "error", err)
		}

		if currentTime.After(expireTime) && cert.CertStatus == 0 {
			_, err := db.Exec("UPDATE certs SET cert_status = 1 WHERE id = ?", cert.Id)
			if err != nil {
				slog.Error("CheckValidCerts: Error updating certificate status", "domain", cert.Domain, "id", cert.Id, "error", err)
			} else {
				slog.Warn("CheckValidCerts: Certificate expired and marked as invalid", "domain", cert.Domain, "id", cert.Id)
				expiredCount++
			}
		}
	}

	// Обновляем days_left у клиентских сертификатов; cert_status меняем только с 0 → 1
	for _, cert := range userCertificates {
		expireTime, err := time.Parse(time.RFC3339, cert.CertExpireTime)
		if err != nil {
			slog.Error("CheckValidCerts: Expiration time parsing error for certificate", "common_name", cert.CommonName, "id", cert.Id, "error", err)
			continue
		}

		daysLeft := calculateDaysLeft(expireTime)

		_, err = db.Exec("UPDATE user_certs SET days_left = ? WHERE id = ?", daysLeft, cert.Id)
		if err != nil {
			slog.Error("CheckValidCerts: Error updating days_left for certificate", "common_name", cert.CommonName, "id", cert.Id, "error", err)
		}

		if currentTime.After(expireTime) && cert.CertStatus == 0 {
			_, err := db.Exec("UPDATE user_certs SET cert_status = 1 WHERE id = ?", cert.Id)
			if err != nil {
				slog.Error("CheckValidCerts: Error updating certificate status", "common_name", cert.CommonName, "id", cert.Id, "error", err)
			} else {
				slog.Warn("CheckValidCerts: Certificate expired and marked as invalid", "common_name", cert.CommonName, "id", cert.Id)
				expiredCount++
			}
		}
	}

	// Обновляем days_left у внешних CA сертификатов; cert_status меняем только с 0 → 1
	for _, cert := range extCACertificates {
		expireTime, err := time.Parse(time.RFC3339, cert.CertExpireTime)
		if err != nil {
			slog.Error("CheckValidCerts: Expiration time parsing error for ext CA certificate", "common_name", cert.CommonName, "id", cert.Id, "error", err)
			continue
		}

		daysLeft := calculateDaysLeft(expireTime)

		_, err = db.Exec("UPDATE ca_certs_ext SET days_left = ? WHERE id = ?", daysLeft, cert.Id)
		if err != nil {
			slog.Error("CheckValidCerts: Error updating days_left for ext CA certificate", "common_name", cert.CommonName, "id", cert.Id, "error", err)
		}

		if currentTime.After(expireTime) && cert.CertStatus == 0 {
			_, err := db.Exec("UPDATE ca_certs_ext SET cert_status = 1 WHERE id = ?", cert.Id)
			if err != nil {
				slog.Error("CheckValidCerts: Error updating ext CA certificate status", "common_name", cert.CommonName, "id", cert.Id, "error", err)
			} else {
				slog.Warn("CheckValidCerts: Ext CA certificate expired and marked as invalid", "common_name", cert.CommonName, "id", cert.Id)
				expiredCount++
			}
		}
	}

	slog.Info("CheckValidCerts: Certificate validation check completed. Updated days_left for all certificates", "expired_count", expiredCount)
	Monitors.CheckValidCerts = time.Now()
}
