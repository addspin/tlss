package check

import (
	"log"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/addspin/tlss/utils"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RecreateCerts(checkRecreateTime time.Duration) {

	switch {
	case viper.GetInt("recreateCerts.time") == 0:
		log.Println("Ошибка в конфигурации: Время пересоздания сертификатов не установлено")
		return
	case viper.GetInt("recreateCerts.time") < 0:
		log.Println("Ошибка в конфигурации: Время пересоздания сертификатов отрицательное")
		return
	case viper.GetString("app.hostname") == "":
		log.Println("Ошибка в конфигурации: Hostname не установлен")
		return
	case viper.GetString("app.port") == "":
		log.Println("Ошибка в конфигурации: Port не установлен")
		return
	}

	log.Println("Запуск модуля повторного создания сертификатов")

	// Выполняем проверку сразу при запуске функции
	checkRecreateCerts()

	ticker := time.NewTicker(checkRecreateTime)
	defer ticker.Stop()

	for range ticker.C {
		log.Println("Запуск проверки на пересоздание сертификатов")
		checkRecreateCerts()
	}
}

func checkRecreateCerts() {

	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Println("Ошибка подключения к базе данных:", err)
		return
	}
	defer db.Close()

	certificates := []models.CertsData{}
	// Извлекаем все записи с типом cert_status = 1 или помеченные на пересоздание recreate = 1
	err = db.Select(&certificates, "SELECT * FROM certs WHERE cert_status = 1 AND recreate = 1")
	if err != nil {
		log.Println("Ошибка запроса сертификатов:", err)
		return
	}

	userCertificate := []models.UserCertsData{}
	err = db.Select(&userCertificate, "SELECT * FROM user_certs WHERE cert_status = 1 AND recreate = 1")
	if err != nil {
		log.Println("Ошибка запроса сертификатов:", err)
		return
	}
	// Сереверные сертификаты
	for _, cert := range certificates {
		// если сертификат сохраняется на сервере, то проверяем, доступен ли сервер
		if cert.SaveOnServer {
			// Извлекаем состояние сервера из базы
			var onlineServerExists bool
			err = db.Get(&onlineServerExists, "SELECT EXISTS(SELECT 1 FROM server WHERE id = ? AND server_status = ?)", cert.ServerId, "online")
			if err != nil {
				log.Println("Ошибка запроса сервера:", err)
				continue
			}
			// Проверяем, доступен ли сервер
			if !onlineServerExists {
				log.Printf("Сервер для сертификата %s (ID: %d) недоступен, пересоздание невозможно", cert.Domain, cert.Id)
				continue
			}

			log.Printf("Сертификат %s (ID: %d) просрочен и будет перевыпущен с сохранением на сервер", cert.Domain, cert.Id)
			certPEM, keyPEM, certErr := crypts.RecreateRSACertificate(&cert, db)

			if certErr != nil {
				log.Printf("Ошибка генерации сертификата: %v", certErr)
				continue
			}
			saveOnServerUtil := utils.NewSaveOnServer()
			err = saveOnServerUtil.SaveOnServer(&cert, db, certPEM, keyPEM)
			if err != nil {
				log.Printf("Ошибка сохранения сертификата на сервер: %v", err)
				continue
			}
		} else {
			// если сертификат не сохраняется на сервере, то пересоздаем его без копирования на сервер
			log.Printf("Сертификат %s (ID: %d) просрочен и будет перевыпущен без сохранения на сервер", cert.Domain, cert.Id)
			_, _, certErr := crypts.RecreateRSACertificate(&cert, db)
			if certErr != nil {
				log.Printf("Ошибка генерации сертификата: %v", certErr)
				continue
			}
		}
	}
	log.Println("Проверка на пересоздание серверных сертификатов завершена")

	// Сертификаты пользователей
	for _, userCert := range userCertificate {
		log.Printf("Сертификат %s (ID: %d) просрочен и будет перевыпущен", userCert.CommonName, userCert.Id)
		certErr := crypts.RecreateUserRSACertificate(&userCert, db)
		if certErr != nil {
			log.Printf("Ошибка генерации сертификата: %v", certErr)
			continue
		}
	}
	log.Println("Проверка на пересоздание пользовательских сертификатов завершена")
}
