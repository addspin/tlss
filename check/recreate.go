package check

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"time"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
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
		log.Println("Сработал тикер, запуск проверки сертификатов")
		checkRecreateCerts()
	}
}

func checkRecreateCerts() {

	log.Println("Повторное создание сертификата начата")

	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Println("Ошибка подключения к базе данных:", err)
		return
	}
	defer db.Close()

	certificates := []models.Certs{}
	// Извлекаем все записи с типом expired = 1 и помеченные на переслоздание recreate = 1
	err = db.Select(&certificates, "SELECT * FROM certs WHERE cert_status = 1 and recreate = 1")
	if err != nil {
		log.Println("Ошибка запроса сертификатов:", err)
		return
	}

	for _, cert := range certificates {
		// Проверяем, доступен ли сервер
		var onlineServerExists bool
		err = db.Get(&onlineServerExists, "SELECT EXISTS(SELECT 1 FROM server WHERE id = ? AND server_status = ?)", cert.ServerId, "online")
		if err != nil {
			log.Println("Ошибка запроса сервера:", err)
			continue
		}

		if !onlineServerExists {
			log.Printf("Сервер для сертификата %s (ID: %d) недоступен, пересоздание невозможно", cert.Domain, cert.Id)
			continue
		}

		// Проверяем, просрочен ли сертификат
		if cert.CertExpireTime < time.Now().Format(time.RFC3339) {
			log.Printf("Сертификат %s (ID: %d) просрочен и будет перевыпущен", cert.Domain, cert.Id)

			postData := cert

			// Преобразуем данные в JSON
			jsonData, err := json.Marshal(postData)
			if err != nil {
				log.Printf("Ошибка преобразования данных сертификата %s в JSON: %v", cert.Domain, err)
				continue
			}

			// Создаем HTTP/HTTPS запрос с API ключом
			var req *http.Request
			req, err = http.NewRequest("POST",
				viper.GetString("app.protocol")+"://"+viper.GetString("app.hostname")+":"+viper.GetString("app.port")+"/add_certs",
				bytes.NewBuffer(jsonData))
			if err != nil {
				log.Printf("Ошибка создания запроса для сертификата %s: %v", cert.Domain, err)
				continue
			}

			// if !viper.GetBool("app.useHTTPS") {
			// 	req, err = http.NewRequest("POST",
			// 		"http://"+viper.GetString("app.hostname")+":"+viper.GetString("app.port")+"/add_certs",
			// 		bytes.NewBuffer(jsonData))
			// 	if err != nil {
			// 		log.Printf("Ошибка создания запроса для сертификата %s: %v", cert.Domain, err)
			// 		continue
			// 	}
			// }

			// Устанавливаем заголовки
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-API-Key", crypts.GetInternalAPIKey())

			// Отправляем запрос
			client := &http.Client{}
			resp, err := client.Do(req)
			if err != nil {
				log.Printf("Ошибка отправки запроса для сертификата %s: %v", cert.Domain, err)
				continue
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				log.Printf("Ошибка при создании сертификата %s: статус %d", cert.Domain, resp.StatusCode)
				continue
			}

			log.Printf("Сертификат %s успешно отправлен на пересоздание", cert.Domain)
		}
	}
}
