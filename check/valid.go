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

	// Получаем все действующие сертификаты с дополнительными полями для расчета days_left
	certificates := []models.CertsData{}
	err = db.Select(&certificates, `SELECT id, domain, cert_create_time, cert_expire_time FROM certs WHERE cert_status = 0`)
	if err != nil {
		slog.Error("CheckValidCerts: Server certificate query error", "error", err)
		return
	}

	userCertificates := []models.UserCertsData{}
	err = db.Select(&userCertificates, "SELECT id, common_name, cert_create_time, cert_expire_time FROM user_certs WHERE cert_status = 0")
	if err != nil {
		slog.Error("CheckValidCerts: Client certificate query error", "error", err)
		return
	}

	caCertificates := []models.CAData{}
	err = db.Select(&caCertificates, "SELECT id, common_name, cert_create_time, cert_expire_time FROM ca_certs WHERE cert_status = 0")
	if err != nil {
		slog.Error("CheckValidCerts: CA certificate query error", "error", err)
		return
	}

	slog.Info("CheckValidCerts: Found active certificates to check", "server_certs", len(certificates), "user_certs", len(userCertificates), "ca_certs", len(caCertificates), "total", len(certificates)+len(userCertificates)+len(caCertificates))

	// Текущее время для сравнения
	currentTime := time.Now()
	// slog.Info("CheckValidCerts: Current time", "time", currentTime.Format(time.RFC3339))

	expiredCount := 0

	// обновляем статус и days_left у CA сертификатов
	for _, cert := range caCertificates {
		// Преобразуем строку времени истечения в объект time.Time
		expireTime, err := time.Parse(time.RFC3339, cert.CertExpireTime)
		if err != nil {
			slog.Error("CheckValidCerts: Expiration time parsing error for certificate", "common_name", cert.CommonName, "id", cert.Id, "error", err)
			continue
		}

		// Вычисляем оставшиеся дни
		daysLeft := calculateDaysLeft(expireTime)

		slog.Info("CheckValidCerts: Certificate", "common_name", cert.CommonName, "id", cert.Id, "expires_at", expireTime.Format(time.RFC3339), "days_left", daysLeft)

		// Обновляем days_left в любом случае
		_, err = db.Exec("UPDATE ca_certs SET days_left = ? WHERE id = ?", daysLeft, cert.Id)
		if err != nil {
			slog.Error("CheckValidCerts: Error updating days_left for certificate", "common_name", cert.CommonName, "id", cert.Id, "error", err)
		}

		// Если сертификат истек
		if currentTime.After(expireTime) {
			slog.Info("CheckValidCerts: Certificate expired", "current_time", currentTime.Format(time.RFC3339), "expire_time", expireTime.Format(time.RFC3339))
			// Обновляем статус на истекший (1)
			_, err := db.Exec("UPDATE ca_certs SET cert_status = 1 WHERE id = ?", cert.Id)
			if err != nil {
				slog.Error("CheckValidCerts: Error updating certificate status", "common_name", cert.CommonName, "id", cert.Id, "error", err)
			} else {
				slog.Warn("CheckValidCerts: Certificate expired and marked as invalid", "common_name", cert.CommonName, "id", cert.Id)
				expiredCount++
			}
		}
	}

	// Обновляем статус и days_left у серверных сертфикатов
	for _, cert := range certificates {
		// Преобразуем строку времени истечения в объект time.Time
		expireTime, err := time.Parse(time.RFC3339, cert.CertExpireTime)
		if err != nil {
			slog.Error("CheckValidCerts: Expiration time parsing error for certificate", "domain", cert.Domain, "id", cert.Id, "error", err)
			continue
		}

		// Вычисляем оставшиеся дни
		daysLeft := calculateDaysLeft(expireTime)

		slog.Info("CheckValidCerts: Certificate", "domain", cert.Domain, "id", cert.Id, "expires_at", expireTime.Format(time.RFC3339), "days_left", daysLeft)

		// Обновляем days_left в любом случае
		_, err = db.Exec("UPDATE certs SET days_left = ? WHERE id = ?", daysLeft, cert.Id)
		if err != nil {
			slog.Error("CheckValidCerts: Error updating days_left for certificate", "domain", cert.Domain, "id", cert.Id, "error", err)
		}

		// Если сертификат истек
		if currentTime.After(expireTime) {
			slog.Info("CheckValidCerts: Certificate expired", "current_time", currentTime.Format(time.RFC3339), "expire_time", expireTime.Format(time.RFC3339))
			// Обновляем статус на истекший (1)
			_, err := db.Exec("UPDATE certs SET cert_status = 1 WHERE id = ?", cert.Id)
			if err != nil {
				slog.Error("CheckValidCerts: Error updating certificate status", "domain", cert.Domain, "id", cert.Id, "error", err)
			} else {
				slog.Warn("CheckValidCerts: Certificate expired and marked as invalid", "domain", cert.Domain, "id", cert.Id)
				expiredCount++
			}
		}
	}

	// Обновляем статус и days_left у клиентских сертификатов
	for _, cert := range userCertificates {
		// Преобразуем строку времени истечения в объект time.Time
		expireTime, err := time.Parse(time.RFC3339, cert.CertExpireTime)
		if err != nil {
			slog.Error("CheckValidCerts: Expiration time parsing error for certificate", "common_name", cert.CommonName, "id", cert.Id, "error", err)
			continue
		}

		// Вычисляем оставшиеся дни
		daysLeft := calculateDaysLeft(expireTime)

		slog.Info("CheckValidCerts: Certificate", "common_name", cert.CommonName, "id", cert.Id, "expires_at", expireTime.Format(time.RFC3339), "days_left", daysLeft)

		// Обновляем days_left в любом случае
		_, err = db.Exec("UPDATE user_certs SET days_left = ? WHERE id = ?", daysLeft, cert.Id)
		if err != nil {
			slog.Error("CheckValidCerts: Error updating days_left for certificate", "common_name", cert.CommonName, "id", cert.Id, "error", err)
		}

		// Если сертификат истек
		if currentTime.After(expireTime) {
			slog.Info("CheckValidCerts: Certificate expired", "current_time", currentTime.Format(time.RFC3339), "expire_time", expireTime.Format(time.RFC3339))
			// Обновляем статус на истекший (1)
			_, err := db.Exec("UPDATE user_certs SET cert_status = 1 WHERE id = ?", cert.Id)
			if err != nil {
				slog.Error("CheckValidCerts: Error updating certificate status", "common_name", cert.CommonName, "id", cert.Id, "error", err)
			} else {
				slog.Warn("CheckValidCerts: Certificate expired and marked as invalid", "common_name", cert.CommonName, "id", cert.Id)
				expiredCount++
			}
		}
	}

	slog.Info("CheckValidCerts: Certificate validation check completed. Updated days_left for all certificates", "expired_count", expiredCount)
	Monitors.CheckValidCerts = time.Now()
}
