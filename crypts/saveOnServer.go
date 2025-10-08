package crypts

import (
	"fmt"
	"log"
	"strconv"

	"github.com/addspin/tlss/models"
	"github.com/addspin/tlss/utils"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

const (
	rootCAPEM      = "root_ca_tlss.pem"
	subCAPEM       = "sub_ca_tlss.pem"
	bundleCAPEMcrl = "bundlecaPEM.crl"
	bundleCADERcrl = "bundlecaDER.crl"
)

type SaveOnServerInterface interface {
	SaveOnServer(data *models.CertsData, db *sqlx.DB, certPEM []byte, keyPEM []byte) error
}

type saveOnServer struct{}

// Общий ssh клиент для подключения к серверу, расшифровывает приватный ключ и подключается к серверу
func sshClient(key models.SSHKey, port int, username, serverName string) (*ssh.Client, error) {

	aes := Aes{}
	decryptPrivKey, err := aes.Decrypt(([]byte(key.PrivateKey)), AesSecretKey.Key)
	if err != nil {
		log.Fatalf("rsaSSH: ошибка расшифровки приватного ключа %v", err)
	}

	signer, err := ssh.ParsePrivateKey(decryptPrivKey)
	if err != nil {
		log.Fatalf("rsaSSH: ошибка, невозможно получить приватный ключ %v", err)
	}

	keyConfig := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		// HostKeyCallback: ssh.FixedHostKey(parsedPubKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         utils.SelectTime(viper.GetString("add_server.unit"), viper.GetInt("add_server.waitingToConnect")),
	}
	client, err := ssh.Dial("tcp", serverName+":"+strconv.Itoa(port), keyConfig)
	if err != nil {
		return nil, fmt.Errorf("не удалось подключиться к серверу: %w", err)
	}
	return client, nil
}

// executeSSHCommand выполняет команду на удаленном сервере
func executeSSHCommand(client *ssh.Client, command string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("не удалось создать SSH сессию: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return output, fmt.Errorf("ошибка выполнения команды: %w", err)
	}

	return output, nil
}

func (s *saveOnServer) SaveOnServer(data *models.CertsData, db *sqlx.DB, certPEM []byte, keyPEM []byte) error {

	// Получаем информацию о сервере для сохранения сертификата
	var serverInfo models.Server
	err := db.Get(&serverInfo, "SELECT id, hostname, port, username, cert_config_path, server_status FROM server WHERE id = ?", data.ServerId)
	if err != nil {
		return fmt.Errorf("не удалось получить информацию о сервере: %w", err)
	}
	// получаем ssh ключ для подключения к серверу по имени сервера
	var sshKey models.SSHKey
	err = db.Get(&sshKey, "SELECT * FROM ssh_key WHERE name_ssh_key = ?", serverInfo.Hostname)
	if err != nil {
		// Если не найден ключ для конкретного сервера, пробуем получить ключ по умолчанию
		err = db.Get(&sshKey, "SELECT * FROM ssh_key WHERE name_ssh_key = ?", "Default")
		if err != nil {
			return fmt.Errorf("не удалось получить ssh ключ: %w", err)
		}
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

	sshClient, err := sshClient(sshKey, serverInfo.Port, serverInfo.Username, serverInfo.Hostname)
	if err != nil {
		return fmt.Errorf("не удалось подключиться к серверу: %w", err)
	}
	defer sshClient.Close()
	// Сохраняем сертификат на сервере в зависимости от типа приложени
	switch data.AppType {
	case "nginx":
		// Создаем пути для файлов сертификата и ключа на удаленном сервере
		certPath := fmt.Sprintf("%s/%s.pem", serverInfo.CertConfigPath, data.Domain)
		keyPath := fmt.Sprintf("%s/%s.key", serverInfo.CertConfigPath, data.Domain)
		subCAPath := fmt.Sprintf("%s/%s", serverInfo.CertConfigPath, subCAPEM)
		rootCAPath := fmt.Sprintf("%s/%s", serverInfo.CertConfigPath, rootCAPEM)

		log.Printf("SaveOnServer: Пути файлов - cert: %s, key: %s, subCA: %s, rootCA: %s",
			certPath, keyPath, subCAPath, rootCAPath)

		// Проверяем существование директории
		checkDirCommand := fmt.Sprintf("test -d %s || { echo 'Директория %s не существует'; exit 1; }",
			serverInfo.CertConfigPath, serverInfo.CertConfigPath)

		log.Printf("SaveOnServer: Проверяем существование директории %s", serverInfo.CertConfigPath)
		output, err := executeSSHCommand(sshClient, checkDirCommand)
		if err != nil {
			log.Printf("SaveOnServer: Директория %s не существует или недоступна: %v, вывод: %s",
				serverInfo.CertConfigPath, err, string(output))
			return fmt.Errorf("директория %s не существует или недоступна: %w", serverInfo.CertConfigPath, err)
		}

		// Сохраняем сертификат сервера
		certCommand := fmt.Sprintf("echo '%s' > %s", string(certPEM), certPath)
		log.Printf("SaveOnServer: Сохраняем сертификат сервера")
		output, err = executeSSHCommand(sshClient, certCommand)
		if err != nil {
			log.Printf("SaveOnServer: Ошибка сохранения сертификата: %v, вывод: %s", err, string(output))
			return fmt.Errorf("не удалось сохранить сертификат: %w", err)
		}

		// Сохраняем приватный ключ
		keyCommand := fmt.Sprintf("echo '%s' > %s && chmod 600 %s", string(keyPEM), keyPath, keyPath)
		log.Printf("SaveOnServer: Сохраняем приватный ключ")
		output, err = executeSSHCommand(sshClient, keyCommand)
		if err != nil {
			log.Printf("SaveOnServer: Ошибка сохранения приватного ключа: %v, вывод: %s", err, string(output))
			return fmt.Errorf("не удалось сохранить приватный ключ: %w", err)
		}

		// Сохраняем промежуточный CA сертификат
		subCACommand := fmt.Sprintf("echo '%s' > %s", subCACert, subCAPath)
		log.Printf("SaveOnServer: Сохраняем промежуточный CA сертификат")
		output, err = executeSSHCommand(sshClient, subCACommand)
		if err != nil {
			log.Printf("SaveOnServer: Ошибка сохранения промежуточного CA: %v, вывод: %s", err, string(output))
			return fmt.Errorf("не удалось сохранить промежуточный CA сертификат: %w", err)
		}

		// Сохраняем корневой CA сертификат
		rootCACommand := fmt.Sprintf("echo '%s' > %s", rootCACert, rootCAPath)
		log.Printf("SaveOnServer: Сохраняем корневой CA сертификат")
		output, err = executeSSHCommand(sshClient, rootCACommand)
		if err != nil {
			log.Printf("SaveOnServer: Ошибка сохранения корневого CA: %v, вывод: %s", err, string(output))
			return fmt.Errorf("не удалось сохранить корневой CA сертификат: %w", err)
		}

		log.Printf("SaveOnServer: Сертификат и ключ успешно сохранены на удаленном сервере %s:%d по путям %s и %s",
			serverInfo.Hostname, serverInfo.Port, certPath, keyPath)

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

		// Объединяем сертификат сервера и его ключ в один файл
		// Порядок: сертификат сервера, промежуточный сертификат, ключ
		combinedContent := fmt.Sprintf("%s\n%s", string(certPEM), string(keyPEM))

		// Путь для сохранения объединенного файла на удаленном сервере
		combinedPath := fmt.Sprintf("%s/%s.pem", serverInfo.CertConfigPath, data.Domain)
		subCAPath := fmt.Sprintf("%s/%s", serverInfo.CertConfigPath, subCAPEM)
		rootCAPath := fmt.Sprintf("%s/%s", serverInfo.CertConfigPath, rootCAPEM)
		bundlePEMCRLPath := fmt.Sprintf("%s/%s", serverInfo.CertConfigPath, bundleCAPEMcrl)

		// Проверяем существование директории
		checkDirCommand := fmt.Sprintf("test -d %s || { echo 'Директория %s не существует'; exit 1; }",
			serverInfo.CertConfigPath, serverInfo.CertConfigPath)
		log.Printf("SaveOnServer: Проверяем существование директории %s", serverInfo.CertConfigPath)
		output, err := executeSSHCommand(sshClient, checkDirCommand)
		if err != nil {
			log.Printf("SaveOnServer: Директория %s не существует или недоступна: %v, вывод: %s",
				serverInfo.CertConfigPath, err, string(output))
			return fmt.Errorf("директория %s не существует или недоступна: %w", serverInfo.CertConfigPath, err)
		}

		// Сохраняем объединенный файл сертификата и ключа
		combinedCommand := fmt.Sprintf("echo '%s' > %s && chmod 600 %s", combinedContent, combinedPath, combinedPath)
		log.Printf("SaveOnServer: Сохраняем объединенный файл сертификата и ключа")
		output, err = executeSSHCommand(sshClient, combinedCommand)
		if err != nil {
			log.Printf("SaveOnServer: Ошибка сохранения объединенного файла: %v, вывод: %s", err, string(output))
			return fmt.Errorf("не удалось сохранить объединенный файл сертификата и ключа: %w", err)
		}

		// Сохраняем промежуточный CA сертификат
		subCACommand := fmt.Sprintf("echo '%s' > %s", subCACert, subCAPath)
		log.Printf("SaveOnServer: Сохраняем промежуточный CA сертификат")
		output, err = executeSSHCommand(sshClient, subCACommand)
		if err != nil {
			log.Printf("SaveOnServer: Ошибка сохранения промежуточного CA: %v, вывод: %s", err, string(output))
			return fmt.Errorf("не удалось сохранить промежуточный CA сертификат: %w", err)
		}

		// Сохраняем корневой CA сертификат
		rootCACommand := fmt.Sprintf("echo '%s' > %s", rootCACert, rootCAPath)
		log.Printf("SaveOnServer: Сохраняем корневой CA сертификат")
		output, err = executeSSHCommand(sshClient, rootCACommand)
		if err != nil {
			log.Printf("SaveOnServer: Ошибка сохранения корневого CA: %v, вывод: %s", err, string(output))
			return fmt.Errorf("не удалось сохранить корневой CA сертификат: %w", err)
		}

		// Сохраняем bundle CRL
		bundleCRLCommand := fmt.Sprintf("echo '%s' > %s", bundleCRL, bundlePEMCRLPath)
		log.Printf("SaveOnServer: Сохраняем bundle CRL")
		output, err = executeSSHCommand(sshClient, bundleCRLCommand)
		if err != nil {
			log.Printf("SaveOnServer: Ошибка сохранения bundle CRL: %v, вывод: %s", err, string(output))
			return fmt.Errorf("не удалось сохранить bundle CRL: %w", err)
		}

		log.Printf("SaveOnServer: Объединенный файл сертификата и ключа успешно сохранен на удаленном сервере %s:%d по пути %s",
			serverInfo.Hostname, serverInfo.Port, combinedPath)

	default:
		log.Printf("Тип приложения %s не поддерживается для сохранения сертификата", data.AppType)
	}
	return nil
}

func NewSaveOnServer() SaveOnServerInterface {
	return &saveOnServer{}
}
