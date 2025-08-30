package utils

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/jmoiron/sqlx"
)

const (
	rootCAFileName       = "root_ca_tlss.pem"
	subCAFileName        = "sub_ca_tlss.pem"
	bundlePEMCRLFileName = "bundle_crl.pem"
	bundleDERCRLFileName = "bundle_crl.der"
)

type SaveOnServerInterface interface {
	SaveOnServer(data *models.CertsData, db *sqlx.DB, certPEM []byte, keyPEM []byte) error
}

type saveOnServer struct{}

func (s *saveOnServer) SaveOnServer(data *models.CertsData, db *sqlx.DB, certPEM []byte, keyPEM []byte) error {

	// Получаем информацию о сервере для сохранения сертификата
	var serverInfo models.Server
	err := db.Get(&serverInfo, "SELECT id, hostname, port, username, cert_config_path, server_status FROM server WHERE id = ?", data.ServerId)
	if err != nil {
		return fmt.Errorf("не удалось получить информацию о сервере: %w", err)
	}

	// Извлекаем Sub CA из таблицы ca_certs
	var subCACert string
	err = db.Get(&subCACert, "SELECT public_key FROM ca_certs WHERE type_ca = 'Sub' AND cert_status = 0")
	if err != nil {
		return fmt.Errorf("не удалось получить промежуточный сертификат: %w", err)
	}

	// Получаем корневой сертификат из таблицы ca_certs
	var rootCACert string
	err = db.Get(&rootCACert, "SELECT public_key FROM ca_certs WHERE type_ca = 'Root' AND cert_status = 0")
	if err != nil {
		return fmt.Errorf("не удалось получить корневой сертификат: %w", err)
	}

	// Получаем домашний каталог пользователя
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return fmt.Errorf("не удалось определить домашний каталог пользователя: %w", err)
	}

	dataTest := NewTestData()
	port, err := dataTest.TestString(serverInfo.Port)
	if err != nil {
		return fmt.Errorf("не удалось преобразовать порт в строку: %w", err)
	}

	// Сохраняем сертификат на сервере в зависимости от типа приложения
	switch data.AppType {
	case "nginx":
		// Создаем пути для файлов сертификата и ключа на удаленном сервере
		certPath := fmt.Sprintf("%s/%s.pem", serverInfo.CertConfigPath, data.Domain)
		keyPath := fmt.Sprintf("%s/%s.key", serverInfo.CertConfigPath, data.Domain)
		subCAPath := fmt.Sprintf("%s/%s", serverInfo.CertConfigPath, subCAFileName)
		rootCAPath := fmt.Sprintf("%s/%s", serverInfo.CertConfigPath, rootCAFileName)

		// Используем ssh клиент для передачи сертификата и ключа
		// Создаём контекст с таймаутом для SSH-команд
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		certCmd := exec.CommandContext(ctx, "ssh",
			"-i", fmt.Sprintf("%s/.ssh/id_rsa_tlss", homeDir),
			"-o", "StrictHostKeyChecking=no",
			"-p", port,
			fmt.Sprintf("%s@%s", serverInfo.Username, serverInfo.Hostname),
			fmt.Sprintf("test -d %s || { echo 'Директория %s не существует'; exit 1; } && echo '%s' > %s && echo '%s' > %s && echo '%s' > %s",
				serverInfo.CertConfigPath, serverInfo.CertConfigPath, string(certPEM), certPath, subCACert, subCAPath, rootCACert, rootCAPath))

		// Выполняем команды и проверяем результат
		if err = certCmd.Run(); err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("таймаут при попытке сохранить сертификат на удаленном сервере: %w", err)
			}
			return fmt.Errorf("не удалось сохранить сертификат (тип приложения: %s) на удаленном сервере: %w", data.AppType, err)
		}

		keyCmd := exec.CommandContext(ctx, "ssh",
			"-i", fmt.Sprintf("%s/.ssh/id_rsa_tlss", homeDir),
			"-o", "StrictHostKeyChecking=no",
			"-p", port,
			fmt.Sprintf("%s@%s", serverInfo.Username, serverInfo.Hostname),
			fmt.Sprintf("test -d %s || { echo 'Директория %s не существует'; exit 1; } && echo '%s' > %s && chmod 600 %s",
				serverInfo.CertConfigPath, serverInfo.CertConfigPath, string(keyPEM), keyPath, keyPath))

		if err = keyCmd.Run(); err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("таймаут при попытке сохранить ключ на удаленном сервере: %w", err)
			}
			return fmt.Errorf("не удалось сохранить ключ (тип приложения: %s) на удаленном сервере: %w", data.AppType, err)
		}

		log.Printf("Сертификат и ключ успешно сохранены на удаленном сервере %s:%s по путям %s и %s",
			serverInfo.Hostname, port, certPath, keyPath)

	case "haproxy":
		// Для HAProxy нужно объединить сертификат сервера и ключ в один файл
		// Получаем промежуточный сертификат из таблицы ca_certs
		var subCACert string
		err = db.Get(&subCACert, "SELECT public_key FROM ca_certs WHERE type_ca = 'Sub' AND cert_status = 0")
		if err != nil {
			return fmt.Errorf("не удалось получить промежуточный сертификат: %w", err)
		}

		// Получаем корневой сертификат из таблицы ca_certs
		var rootCACert string
		err = db.Get(&rootCACert, "SELECT public_key FROM ca_certs WHERE type_ca = 'Root' AND cert_status = 0")
		if err != nil {
			return fmt.Errorf("не удалось получить корневой сертификат: %w", err)
		}

		// получаем bundle crl
		var bundleCRL string
		err = db.Get(&bundleCRL, "SELECT data_crl FROM crl WHERE type_crl = 'Bundle'")
		if err != nil {
			return fmt.Errorf("не удалось получить bundle crl: %w", err)
		}

		// Объединяем промежуточный сертификат, сертификат сервера и его ключ в один файл
		// Порядок: сертификат сервера, промежуточный сертификат, ключ
		combinedContent := fmt.Sprintf("%s\n%s", string(certPEM), string(keyPEM))

		// Путь для сохранения объединенного файла на удаленном сервере
		combinedPath := fmt.Sprintf("%s/%s.pem", serverInfo.CertConfigPath, data.Domain)
		subCAPath := fmt.Sprintf("%s/%s", serverInfo.CertConfigPath, subCAFileName)
		rootCAPath := fmt.Sprintf("%s/%s", serverInfo.CertConfigPath, rootCAFileName)
		bundlePEMCRLPath := fmt.Sprintf("%s/%s", serverInfo.CertConfigPath, bundlePEMCRLFileName)

		// Используем ssh клиент для передачи объединенного файла
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		combinedCmd := exec.CommandContext(ctx, "ssh",
			"-i", fmt.Sprintf("%s/.ssh/id_rsa_tlss", homeDir),
			"-o", "StrictHostKeyChecking=no",
			"-p", port,
			fmt.Sprintf("%s@%s", serverInfo.Username, serverInfo.Hostname),
			fmt.Sprintf("test -d %s || { echo 'Директория %s не существует'; exit 1; } && echo '%s' > %s && echo '%s' > %s && echo '%s' > %s && chmod 600 %s && echo '%s' > %s",
				serverInfo.CertConfigPath, serverInfo.CertConfigPath, combinedContent, combinedPath, subCACert, subCAPath, rootCACert, rootCAPath, combinedPath, bundlePEMCRLPath, bundleCRL))

		// Выполняем команду и проверяем результат
		if err = combinedCmd.Run(); err != nil {
			if ctx.Err() == context.DeadlineExceeded {
				return fmt.Errorf("таймаут при попытке сохранить объединенный файл сертификата и ключа на удаленном сервере: %w", err)
			}
			return fmt.Errorf("не удалось сохранить объединенный файл сертификата и ключа (тип приложения: %s) на удаленном сервере: %w", data.AppType, err)
		}

		log.Printf("Объединенный файл сертификата и ключа успешно сохранен на удаленном сервере %s:%s по пути %s",
			serverInfo.Hostname, port, combinedPath)

	default:
		log.Printf("Тип приложения %s не поддерживается для сохранения сертификата", data.AppType)
	}
	return nil
}

func NewSaveOnServer() SaveOnServerInterface {
	return &saveOnServer{}
}

// Если все операции прошли успешно, фиксируем транзакцию
// if err = tx.Commit(); err != nil {
// 	return fmt.Errorf("не удалось зафиксировать транзакцию: %w", err)
// }
// txCommitted = true
