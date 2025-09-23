package check

import (
	"log"
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
	log.Println("CheckValidCerts: Запуск модуля проверки валидности сертификатов")

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
	log.Println("CheckValidCerts: Проверка валидности сертификатов начата")

	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Println("CheckValidCerts: Ошибка подключения к базе данных:", err)
		return
	}
	defer db.Close()

	// Получаем все действующие сертификаты с дополнительными полями для расчета days_left
	certificates := []models.CertsData{}
	err = db.Select(&certificates, `SELECT id, domain, cert_create_time, cert_expire_time FROM certs WHERE cert_status = 0`)
	if err != nil {
		log.Println("CheckValidCerts: Ошибка запроса серверных сертификатов:", err)
		return
	}

	userCertificates := []models.UserCertsData{}
	err = db.Select(&userCertificates, "SELECT id, common_name, cert_create_time, cert_expire_time FROM user_certs WHERE cert_status = 0")
	if err != nil {
		log.Println("CheckValidCerts: Ошибка запроса клиентских сертификатов:", err)
		return
	}

	caCertificates := []models.CAData{}
	err = db.Select(&caCertificates, "SELECT id, common_name, cert_create_time, cert_expire_time FROM ca_certs WHERE cert_status = 0")
	if err != nil {
		log.Println("CheckValidCerts: Ошибка запроса CA сертификатов:", err)
		return
	}

	log.Printf("CheckValidCerts: Найдено действующих сертификатов для проверки: серверные=%d, пользовательские=%d, CA=%d, итого=%d", len(certificates), len(userCertificates), len(caCertificates), len(certificates)+len(userCertificates)+len(caCertificates))

	// Текущее время для сравнения
	currentTime := time.Now()
	// log.Printf("CheckValidCerts: Текущее время: %s", currentTime.Format(time.RFC3339))

	expiredCount := 0

	// обновляем статус и days_left у CA сертификатов
	for _, cert := range caCertificates {
		// Преобразуем строку времени истечения в объект time.Time
		expireTime, err := time.Parse(time.RFC3339, cert.CertExpireTime)
		if err != nil {
			log.Printf("CheckValidCerts: Ошибка парсинга времени истечения для сертификата %s (ID: %d): %v", cert.CommonName, cert.Id, err)
			continue
		}

		// Вычисляем оставшиеся дни
		daysLeft := calculateDaysLeft(expireTime)

		log.Printf("CheckValidCerts: Сертификат %s (ID: %d), срок действия до: %s, осталось дней: %d", cert.CommonName, cert.Id, expireTime.Format(time.RFC3339), daysLeft)

		// Обновляем days_left в любом случае
		_, err = db.Exec("UPDATE ca_certs SET days_left = ? WHERE id = ?", daysLeft, cert.Id)
		if err != nil {
			log.Printf("CheckValidCerts: Ошибка обновления days_left для сертификата %s (ID: %d): %v", cert.CommonName, cert.Id, err)
		}

		// Если сертификат истек
		if currentTime.After(expireTime) {
			log.Printf("CheckValidCerts: currentTime: %s, expireTime: %s", currentTime.Format(time.RFC3339), expireTime.Format(time.RFC3339))
			// Обновляем статус на истекший (1)
			_, err := db.Exec("UPDATE ca_certs SET cert_status = 1 WHERE id = ?", cert.Id)
			if err != nil {
				log.Printf("CheckValidCerts: Ошибка обновления статуса сертификата %s (ID: %d): %v", cert.CommonName, cert.Id, err)
			} else {
				log.Printf("CheckValidCerts: Сертификат для домена %s (ID: %d) истёк и помечен как недействительный", cert.CommonName, cert.Id)
				expiredCount++
			}
		}
	}

	// Обновляем статус и days_left у серверных сертфикатов
	for _, cert := range certificates {
		// Преобразуем строку времени истечения в объект time.Time
		expireTime, err := time.Parse(time.RFC3339, cert.CertExpireTime)
		if err != nil {
			log.Printf("CheckValidCerts: Ошибка парсинга времени истечения для сертификата %s (ID: %d): %v", cert.Domain, cert.Id, err)
			continue
		}

		// Вычисляем оставшиеся дни
		daysLeft := calculateDaysLeft(expireTime)

		log.Printf("CheckValidCerts: Сертификат %s (ID: %d), срок действия до: %s, осталось дней: %d", cert.Domain, cert.Id, expireTime.Format(time.RFC3339), daysLeft)

		// Обновляем days_left в любом случае
		_, err = db.Exec("UPDATE certs SET days_left = ? WHERE id = ?", daysLeft, cert.Id)
		if err != nil {
			log.Printf("CheckValidCerts: Ошибка обновления days_left для сертификата %s (ID: %d): %v", cert.Domain, cert.Id, err)
		}

		// Если сертификат истек
		if currentTime.After(expireTime) {
			log.Printf("CheckValidCerts: currentTime: %s, expireTime: %s", currentTime.Format(time.RFC3339), expireTime.Format(time.RFC3339))
			// Обновляем статус на истекший (1)
			_, err := db.Exec("UPDATE certs SET cert_status = 1 WHERE id = ?", cert.Id)
			if err != nil {
				log.Printf("CheckValidCerts: Ошибка обновления статуса сертификата %s (ID: %d): %v", cert.Domain, cert.Id, err)
			} else {
				log.Printf("CheckValidCerts: Сертификат для домена %s (ID: %d) истёк и помечен как недействительный", cert.Domain, cert.Id)
				expiredCount++
			}
		}
	}

	// Обновляем статус и days_left у клиентских сертификатов
	for _, cert := range userCertificates {
		// Преобразуем строку времени истечения в объект time.Time
		expireTime, err := time.Parse(time.RFC3339, cert.CertExpireTime)
		if err != nil {
			log.Printf("CheckValidCerts: Ошибка парсинга времени истечения для сертификата %s (ID: %d): %v", cert.CommonName, cert.Id, err)
			continue
		}

		// Вычисляем оставшиеся дни
		daysLeft := calculateDaysLeft(expireTime)

		log.Printf("CheckValidCerts: Сертификат %s (ID: %d), срок действия до: %s, осталось дней: %d", cert.CommonName, cert.Id, expireTime.Format(time.RFC3339), daysLeft)

		// Обновляем days_left в любом случае
		_, err = db.Exec("UPDATE user_certs SET days_left = ? WHERE id = ?", daysLeft, cert.Id)
		if err != nil {
			log.Printf("CheckValidCerts: Ошибка обновления days_left для сертификата %s (ID: %d): %v", cert.CommonName, cert.Id, err)
		}

		// Если сертификат истек
		if currentTime.After(expireTime) {
			log.Printf("CheckValidCerts: currentTime: %s, expireTime: %s", currentTime.Format(time.RFC3339), expireTime.Format(time.RFC3339))
			// Обновляем статус на истекший (1)
			_, err := db.Exec("UPDATE user_certs SET cert_status = 1 WHERE id = ?", cert.Id)
			if err != nil {
				log.Printf("CheckValidCerts: Ошибка обновления статуса сертификата %s (ID: %d): %v", cert.CommonName, cert.Id, err)
			} else {
				log.Printf("CheckValidCerts: Сертификат для %s (ID: %d) истёк и помечен как недействительный", cert.CommonName, cert.Id)
				expiredCount++
			}
		}
	}

	log.Printf("CheckValidCerts: Проверка валидности сертификатов завершена. Обновлены days_left для всех сертификатов. Обновлено статусов (истёкших): %d", expiredCount)
	Monitors.CheckValidCerts = time.Now()
}
