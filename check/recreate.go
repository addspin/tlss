package check

import (
	"log/slog"
	"time"

	"github.com/addspin/tlss/controllers/caControllers"
	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RecreateCerts(checkRecreateTime time.Duration) {

	switch {
	case viper.GetInt("recreateCerts.recreateCertsInterval") == 0:
		slog.Error("RecreateCerts: Configuration error: Certificate recreation time is not set")
		return
	case viper.GetInt("recreateCerts.recreateCertsInterval") < 0:
		slog.Error("RecreateCerts: Configuration error: Certificate recreation time is negative")
		return
	case viper.GetString("app.hostname") == "":
		slog.Error("RecreateCerts: Configuration error: Hostname is not set")
		return
	case viper.GetString("app.port") == "":
		slog.Error("RecreateCerts: Configuration error: Port is not set")
		return
	}

	slog.Info("RecreateCerts: Starting certificate recreation module")

	// Выполняем проверку сразу при запуске функции
	checkRecreateCerts()

	ticker := time.NewTicker(checkRecreateTime)
	defer ticker.Stop()

	for range ticker.C {
		slog.Info("RecreateCerts: Starting certificate recreation check")
		checkRecreateCerts()
	}
}

func checkRecreateCerts() {

	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("RecreateCerts: Database connection error", "error", err)
		return
	}
	defer db.Close()

	certificates := []models.CertsData{}
	// Извлекаем все записи с типом cert_status = 1 или помеченные на пересоздание recreate = 1
	err = db.Select(&certificates, "SELECT * FROM certs WHERE cert_status = 1 AND recreate = 1")
	if err != nil {
		slog.Error("RecreateCerts: Certificate query error", "error", err)
		return
	}

	userCertificate := []models.UserCertsData{}
	err = db.Select(&userCertificate, "SELECT * FROM user_certs WHERE cert_status = 1 AND recreate = 1")
	if err != nil {
		slog.Error("RecreateCerts: Certificate query error", "error", err)
		return
	}

	caCertificates := []models.CAData{}
	err = db.Select(&caCertificates, "SELECT * FROM ca_certs WHERE cert_status = 1 AND recreate = 1")
	if err != nil {
		slog.Error("RecreateCerts: CA certificate query error", "error", err)
		return
	}

	// CA сертификаты
	for _, cert := range caCertificates {
		slog.Info("RecreateCerts: CA certificate expired and will be reissued", "common_name", cert.CommonName, "id", cert.Id)
		certErr := caControllers.CreateCACertRSA(&cert, db)
		if certErr != nil {
			slog.Error("RecreateCerts: Certificate generation error", "error", certErr)
			continue
		}
	}
	slog.Info("RecreateCerts: CA certificate recreation check completed")

	// Сереверные сертификаты
	for _, cert := range certificates {
		// если сертификат сохраняется на сервере, то проверяем, доступен ли сервер
		if cert.SaveOnServer {
			// Извлекаем состояние сервера из базы
			var onlineServerExists bool
			err = db.Get(&onlineServerExists, "SELECT EXISTS(SELECT 1 FROM server WHERE id = ? AND server_status = ?)", cert.ServerId, "online")
			if err != nil {
				slog.Error("RecreateCerts: Server query error", "error", err)
				continue
			}
			// Проверяем, доступен ли сервер
			if !onlineServerExists {
				slog.Warn("RecreateCerts: Server for certificate is unavailable, recreation is impossible", "domain", cert.Domain, "id", cert.Id)
				continue
			}

			slog.Info("RecreateCerts: Certificate expired and will be reissued with saving to server", "domain", cert.Domain, "id", cert.Id, "algorithm", cert.Algorithm)

			// Выбираем функцию пересоздания в зависимости от алгоритма
			var certPEM, keyPEM []byte
			var certErr error
			switch cert.Algorithm {
			case "RSA":
				certPEM, keyPEM, certErr = crypts.RecreateRSACertificate(&cert, db)
			case "ED25519":
				certPEM, keyPEM, certErr = crypts.RecreateED25519Certificate(&cert, db)
			case "ECDSA":
				certPEM, keyPEM, certErr = crypts.RecreateECDSACertificate(&cert, db)
			default:
				slog.Error("RecreateCerts: Unsupported algorithm for certificate", "algorithm", cert.Algorithm, "domain", cert.Domain, "id", cert.Id)
				continue
			}

			if certErr != nil {
				slog.Error("RecreateCerts: Certificate generation error", "error", certErr)
				continue
			}
			saveOnServerUtil := crypts.NewSaveOnServer()
			err = saveOnServerUtil.SaveOnServer(&cert, db, certPEM, keyPEM)
			if err != nil {
				slog.Error("RecreateCerts: Error saving certificate to server", "error", err)
				continue
			}
		} else {
			// если сертификат не сохраняется на сервере, то пересоздаем его без копирования на сервер
			slog.Info("RecreateCerts: Certificate expired and will be reissued without saving to server", "domain", cert.Domain, "id", cert.Id, "algorithm", cert.Algorithm)

			// Выбираем функцию пересоздания в зависимости от алгоритма
			var certErr error
			switch cert.Algorithm {
			case "RSA":
				_, _, certErr = crypts.RecreateRSACertificate(&cert, db)
			case "ED25519":
				_, _, certErr = crypts.RecreateED25519Certificate(&cert, db)
			case "ECDSA":
				_, _, certErr = crypts.RecreateECDSACertificate(&cert, db)
			default:
				slog.Error("RecreateCerts: Unsupported algorithm for certificate", "algorithm", cert.Algorithm, "domain", cert.Domain, "id", cert.Id)
				continue
			}

			if certErr != nil {
				slog.Error("RecreateCerts: Certificate generation error", "error", certErr)
				continue
			}
		}
	}
	slog.Info("RecreateCerts: Server certificate recreation check completed")

	// Сертификаты пользователей
	for _, userCert := range userCertificate {
		slog.Info("RecreateCerts: User certificate expired and will be reissued", "common_name", userCert.CommonName, "id", userCert.Id, "algorithm", userCert.Algorithm)

		// Выбираем функцию пересоздания в зависимости от алгоритма
		var certErr error
		switch userCert.Algorithm {
		case "RSA":
			certErr = crypts.RecreateUserRSACertificate(&userCert, db)
		case "ED25519":
			certErr = crypts.RecreateUserED25519Certificate(&userCert, db)
		case "ECDSA":
			certErr = crypts.RecreateUserECDSACertificate(&userCert, db)
		default:
			slog.Error("RecreateCerts: Unsupported algorithm for user certificate", "algorithm", userCert.Algorithm, "common_name", userCert.CommonName, "id", userCert.Id)
			continue
		}

		if certErr != nil {
			slog.Error("RecreateCerts: User certificate generation error", "error", certErr)
			continue
		}
	}
	slog.Info("RecreateCerts: User certificate recreation check completed")
	Monitors.RecreateCerts = time.Now()
}
