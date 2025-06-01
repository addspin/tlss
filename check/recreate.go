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
	// Извлекаем все записи с типом expired = 1 или помеченные на пересоздание recreate = 1
	err = db.Select(&certificates, "SELECT * FROM certs WHERE cert_status = 1 OR recreate = 1")
	if err != nil {
		log.Println("Ошибка запроса сертификатов:", err)
		return
	}

	for _, cert := range certificates {
		// если сертификат сохраняется на сервере, то проверяем, доступен ли сервер
		saveOnServer, err := utils.NewTestData().TestBool(cert.SaveOnServer)
		if err != nil {
			log.Println("Ошибка запроса сервера:", err)
			continue
		}

		id, err := utils.NewTestData().TestInt(cert.Id)
		if err != nil {
			log.Println("Ошибка получения ID сертификата:", err)
			continue
		}

		// Проверяем, просрочен ли сертификат
		// if cert.CertExpireTime >= time.Now().Format(time.RFC3339) {
		// 	log.Printf("Сертификат %s (ID: %d) еще не просрочен, пропускаем", cert.Domain, id)
		// 	continue
		// }

		if saveOnServer {
			// Извлекаем состояние сервера из базы
			var onlineServerExists bool
			err = db.Get(&onlineServerExists, "SELECT EXISTS(SELECT 1 FROM server WHERE id = ? AND server_status = ?)", cert.ServerId, "online")
			if err != nil {
				log.Println("Ошибка запроса сервера:", err)
				continue
			}
			// Проверяем, доступен ли сервер
			if !onlineServerExists {
				log.Printf("Сервер для сертификата %s (ID: %d) недоступен, пересоздание невозможно", cert.Domain, id)
				continue
			}

			log.Printf("Сертификат %s (ID: %d) просрочен и будет перевыпущен с сохранением на сервер", cert.Domain, id)
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
			log.Printf("Сертификат %s (ID: %d) просрочен и будет перевыпущен без сохранения на сервер", cert.Domain, id)
			_, _, certErr := crypts.RecreateRSACertificate(&cert, db)
			if certErr != nil {
				log.Printf("Ошибка генерации сертификата: %v", certErr)
				continue
			}
		}
	}
}
