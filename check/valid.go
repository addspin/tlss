package check

import (
	"log"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

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

	// Получаем все действующие сертификаты
	certificates := []models.CertsData{}
	err = db.Select(&certificates, `SELECT id, domain, cert_expire_time FROM certs WHERE cert_status = 0`)
	if err != nil {
		log.Println("CheckValidCerts: Ошибка запроса сертификатов:", err)
		return
	}

	userCertificates := []models.UserCertsData{}
	err = db.Select(&userCertificates, "SELECT * FROM user_certs WHERE cert_status = 0")
	if err != nil {
		log.Println("CheckValidCerts: Ошибка запроса сертификатов:", err)
		return
	}

	log.Printf("CheckValidCerts: Найдено %d действующих сертификатов для проверки", len(certificates))

	// Текущее время для сравнения
	currentTime := time.Now()
	// log.Printf("CheckValidCerts: Текущее время: %s", currentTime.Format(time.RFC3339))

	expiredCount := 0

	// Проверяем каждый сертификат
	for _, cert := range certificates {
		// Преобразуем строку времени истечения в объект time.Time
		expireTime, err := time.Parse(time.RFC3339, cert.CertExpireTime)
		if err != nil {
			log.Printf("CheckValidCerts: Ошибка парсинга времени истечения для сертификата %s (ID: %d): %v", cert.Domain, cert.Id, err)
			continue
		}

		log.Printf("CheckValidCerts: Сертификат %s (ID: %d), срок действия до: %s", cert.Domain, cert.Id, expireTime.Format(time.RFC3339))

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

	for _, cert := range userCertificates {
		// Преобразуем строку времени истечения в объект time.Time
		expireTime, err := time.Parse(time.RFC3339, cert.CertExpireTime)
		if err != nil {
			log.Printf("CheckValidCerts: Ошибка парсинга времени истечения для сертификата %s (ID: %d): %v", cert.CommonName, cert.Id, err)
			continue
		}

		log.Printf("CheckValidCerts: Сертификат %s (ID: %d), срок действия до: %s", cert.CommonName, cert.Id, expireTime.Format(time.RFC3339))

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

	log.Printf("CheckValidCerts: Проверка валидности сертификатов завершена. Обновлено статусов: %d", expiredCount)
}
