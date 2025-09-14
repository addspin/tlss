package check

import (
	"log"
	"time"

	"github.com/addspin/tlss/controllers/caControllers"
	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/addspin/tlss/utils"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RecreateCerts(checkRecreateTime time.Duration) {

	switch {
	case viper.GetInt("recreateCerts.recreateCertsInterval") == 0:
		log.Println("RecreateCerts: Ошибка в конфигурации: Время пересоздания сертификатов не установлено")
		return
	case viper.GetInt("recreateCerts.recreateCertsInterval") < 0:
		log.Println("RecreateCerts: Ошибка в конфигурации: Время пересоздания сертификатов отрицательное")
		return
	case viper.GetString("app.hostname") == "":
		log.Println("RecreateCerts: Ошибка в конфигурации: Hostname не установлен")
		return
	case viper.GetString("app.port") == "":
		log.Println("RecreateCerts: Ошибка в конфигурации: Port не установлен")
		return
	}

	log.Println("RecreateCerts: Запуск модуля повторного создания сертификатов")

	// Выполняем проверку сразу при запуске функции
	checkRecreateCerts()

	ticker := time.NewTicker(checkRecreateTime)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("RecreateCerts: Запуск проверки на пересоздание сертификатов")
		checkRecreateCerts()
	}
}

func checkRecreateCerts() {

	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Println("RecreateCerts: Ошибка подключения к базе данных:", err)
		return
	}
	defer db.Close()

	certificates := []models.CertsData{}
	// Извлекаем все записи с типом cert_status = 1 или помеченные на пересоздание recreate = 1
	err = db.Select(&certificates, "SELECT * FROM certs WHERE cert_status = 1 AND recreate = 1")
	if err != nil {
		log.Println("RecreateCerts: Ошибка запроса сертификатов:", err)
		return
	}

	userCertificate := []models.UserCertsData{}
	err = db.Select(&userCertificate, "SELECT * FROM user_certs WHERE cert_status = 1 AND recreate = 1")
	if err != nil {
		log.Println("RecreateCerts: Ошибка запроса сертификатов:", err)
		return
	}

	caCertificates := []models.CAData{}
	err = db.Select(&caCertificates, "SELECT * FROM ca_certs WHERE cert_status = 1 AND recreate = 1")
	if err != nil {
		log.Println("RecreateCerts: Ошибка запроса CA сертификатов:", err)
		return
	}

	// CA сертификаты
	for _, cert := range caCertificates {
		log.Printf("RecreateCerts: CA сертификат %s (ID: %d) просрочен и будет перевыпущен", cert.CommonName, cert.Id)
		certErr := caControllers.CreateCACertRSA(&cert, db)
		if certErr != nil {
			log.Printf("RecreateCerts: Ошибка генерации сертификата: %v", certErr)
			continue
		}
	}
	log.Println("RecreateCerts: Проверка на пересоздание CA сертификатов завершена")

	// Сереверные сертификаты
	for _, cert := range certificates {
		// если сертификат сохраняется на сервере, то проверяем, доступен ли сервер
		if cert.SaveOnServer {
			// Извлекаем состояние сервера из базы
			var onlineServerExists bool
			err = db.Get(&onlineServerExists, "SELECT EXISTS(SELECT 1 FROM server WHERE id = ? AND server_status = ?)", cert.ServerId, "online")
			if err != nil {
				log.Println("RecreateCerts: Ошибка запроса сервера:", err)
				continue
			}
			// Проверяем, доступен ли сервер
			if !onlineServerExists {
				log.Printf("RecreateCerts: Сервер для сертификата %s (ID: %d) недоступен, пересоздание невозможно", cert.Domain, cert.Id)
				continue
			}

			log.Printf("RecreateCerts: Сертификат %s (ID: %d) просрочен и будет перевыпущен с сохранением на сервер", cert.Domain, cert.Id)
			certPEM, keyPEM, certErr := crypts.RecreateRSACertificate(&cert, db)

			if certErr != nil {
				log.Printf("RecreateCerts: Ошибка генерации сертификата: %v", certErr)
				continue
			}
			saveOnServerUtil := utils.NewSaveOnServer()
			err = saveOnServerUtil.SaveOnServer(&cert, db, certPEM, keyPEM)
			if err != nil {
				log.Printf("RecreateCerts: Ошибка сохранения сертификата на сервер: %v", err)
				continue
			}
		} else {
			// если сертификат не сохраняется на сервере, то пересоздаем его без копирования на сервер
			log.Printf("RecreateCerts: Сертификат %s (ID: %d) просрочен и будет перевыпущен без сохранения на сервер", cert.Domain, cert.Id)
			_, _, certErr := crypts.RecreateRSACertificate(&cert, db)
			if certErr != nil {
				log.Printf("RecreateCerts: Ошибка генерации сертификата: %v", certErr)
				continue
			}
		}
	}
	log.Println("RecreateCerts: Проверка на пересоздание серверных сертификатов завершена")

	// Сертификаты пользователей
	for _, userCert := range userCertificate {
		log.Printf("RecreateCerts: Сертификат %s (ID: %d) просрочен и будет перевыпущен", userCert.CommonName, userCert.Id)
		certErr := crypts.RecreateUserRSACertificate(&userCert, db)
		if certErr != nil {
			log.Printf("RecreateCerts: Ошибка генерации сертификата: %v", certErr)
			continue
		}
	}
	log.Println("RecreateCerts: Проверка на пересоздание пользовательских сертификатов завершена")
	Monitors.RecreateCerts = time.Now()
}
