package crypts

import (
	"fmt"
	"log/slog"
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
		slog.Error("rsaSSH: ошибка расшифровки приватного ключа", slog.Any("error", err))
	}

	signer, err := ssh.ParsePrivateKey(decryptPrivKey)
	if err != nil {
		slog.Error("rsaSSH: ошибка, невозможно получить приватный ключ", slog.Any("error", err))
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
		return nil, fmt.Errorf("failed to connect to server: %w", err)
	}
	return client, nil
}

// executeSSHCommand выполняет команду на удаленном сервере
func executeSSHCommand(client *ssh.Client, command string) ([]byte, error) {
	session, err := client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	output, err := session.CombinedOutput(command)
	if err != nil {
		return output, fmt.Errorf("error executing command: %w", err)
	}

	return output, nil
}

func (s *saveOnServer) SaveOnServer(data *models.CertsData, db *sqlx.DB, certPEM []byte, keyPEM []byte) error {

	// Получаем информацию о сервере для сохранения сертификата
	var serverInfo models.Server
	err := db.Get(&serverInfo, "SELECT id, hostname, port, username, cert_config_path, server_status FROM server WHERE id = ?", data.ServerId)
	if err != nil {
		return fmt.Errorf("failed to get server information: %w", err)
	}
	// получаем ssh ключ для подключения к серверу по имени сервера
	var sshKey models.SSHKey
	err = db.Get(&sshKey, "SELECT * FROM ssh_key WHERE name_ssh_key = ?", serverInfo.Hostname)
	if err != nil {
		// Если не найден ключ для конкретного сервера, пробуем получить ключ по умолчанию
		err = db.Get(&sshKey, "SELECT * FROM ssh_key WHERE name_ssh_key = ?", "Default")
		if err != nil {
			return fmt.Errorf("failed to get SSH key: %w", err)
		}
	}

	// Извлекаем Sub CA из таблицы ca_certs
	var subCACert string
	err = db.Get(&subCACert, "SELECT public_key FROM ca_certs WHERE type_ca = 'Sub' AND cert_status = 0")
	if err != nil {
		return fmt.Errorf("failed to get intermediate certificate: %w", err)
	}

	// Получаем корневой сертификат из таблицы ca_certs
	var rootCACert string
	err = db.Get(&rootCACert, "SELECT public_key FROM ca_certs WHERE type_ca = 'Root' AND cert_status = 0")
	if err != nil {
		return fmt.Errorf("failed to get root certificate: %w", err)
	}

	sshClient, err := sshClient(sshKey, serverInfo.Port, serverInfo.Username, serverInfo.Hostname)
	if err != nil {
		return fmt.Errorf("failed to connect to server: %w", err)
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

		slog.Info("SaveOnServer: Пути файлов - cert", slog.String("certPath", certPath), slog.String("keyPath", keyPath), slog.String("subCAPath", subCAPath), slog.String("rootCAPath", rootCAPath))

		// Проверяем существование директории
		checkDirCommand := fmt.Sprintf("test -d %s || { echo 'Директория %s не существует'; exit 1; }",
			serverInfo.CertConfigPath, serverInfo.CertConfigPath)

		slog.Info("SaveOnServer: Проверяем существование директории", slog.String("path", serverInfo.CertConfigPath))
		output, err := executeSSHCommand(sshClient, checkDirCommand)
		if err != nil {
			slog.Error("SaveOnServer: Директория не существует или недоступна", slog.String("path", serverInfo.CertConfigPath), slog.Any("error", err), slog.String("output", string(output)))
			return fmt.Errorf("directory %s does not exist or is inaccessible: %w", serverInfo.CertConfigPath, err)
		}

		// Сохраняем сертификат сервера
		certCommand := fmt.Sprintf("echo '%s' > %s", string(certPEM), certPath)
		slog.Info("SaveOnServer: Сохраняем сертификат сервера")
		output, err = executeSSHCommand(sshClient, certCommand)
		if err != nil {
			slog.Error("SaveOnServer: Ошибка сохранения сертификата", slog.Any("error", err), slog.String("output", string(output)))
			return fmt.Errorf("failed to save certificate: %w", err)
		}

		// Сохраняем приватный ключ
		keyCommand := fmt.Sprintf("echo '%s' > %s && chmod 600 %s", string(keyPEM), keyPath, keyPath)
		slog.Info("SaveOnServer: Сохраняем приватный ключ")
		output, err = executeSSHCommand(sshClient, keyCommand)
		if err != nil {
			slog.Error("SaveOnServer: Ошибка сохранения приватного ключа", slog.Any("error", err), slog.String("output", string(output)))
			return fmt.Errorf("failed to save private key: %w", err)
		}

		// Сохраняем промежуточный CA сертификат
		subCACommand := fmt.Sprintf("echo '%s' > %s", subCACert, subCAPath)
		slog.Info("SaveOnServer: Сохраняем промежуточный CA сертификат")
		output, err = executeSSHCommand(sshClient, subCACommand)
		if err != nil {
			slog.Error("SaveOnServer: Ошибка сохранения промежуточного CA", slog.Any("error", err), slog.String("output", string(output)))
			return fmt.Errorf("failed to save intermediate CA certificate: %w", err)
		}

		// Сохраняем корневой CA сертификат
		rootCACommand := fmt.Sprintf("echo '%s' > %s", rootCACert, rootCAPath)
		slog.Info("SaveOnServer: Сохраняем корневой CA сертификат")
		output, err = executeSSHCommand(sshClient, rootCACommand)
		if err != nil {
			slog.Error("SaveOnServer: Ошибка сохранения корневого CA", slog.Any("error", err), slog.String("output", string(output)))
			return fmt.Errorf("failed to save root CA certificate: %w", err)
		}

		slog.Info("SaveOnServer: Сертификат и ключ успешно сохранены на удаленном сервере", slog.String("hostname", serverInfo.Hostname), slog.Int("port", serverInfo.Port), slog.String("certPath", certPath), slog.String("keyPath", keyPath))

	case "haproxy":
		// Для HAProxy нужно объединить сертификат сервера и ключ в один файл
		// Получаем промежуточный сертификат из таблицы ca_certs
		var subCACert string
		err = db.Get(&subCACert, "SELECT public_key FROM ca_certs WHERE type_ca = 'Sub' AND cert_status = 0")
		if err != nil {
			return fmt.Errorf("failed to get intermediate certificate: %w", err)
		}

		// Получаем корневой сертификат из таблицы ca_certs
		var rootCACert string
		err = db.Get(&rootCACert, "SELECT public_key FROM ca_certs WHERE type_ca = 'Root' AND cert_status = 0")
		if err != nil {
			return fmt.Errorf("failed to get root certificate: %w", err)
		}

		// получаем bundle crl
		var bundleCRL string
		err = db.Get(&bundleCRL, "SELECT data_crl FROM crl WHERE type_crl = 'Bundle'")
		if err != nil {
			return fmt.Errorf("failed to get bundle CRL: %w", err)
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
		slog.Info("SaveOnServer: Проверяем существование директории", slog.String("path", serverInfo.CertConfigPath))
		output, err := executeSSHCommand(sshClient, checkDirCommand)
		if err != nil {
			slog.Error("SaveOnServer: Директория не существует или недоступна", slog.String("path", serverInfo.CertConfigPath), slog.Any("error", err), slog.String("output", string(output)))
			return fmt.Errorf("directory %s does not exist or is inaccessible: %w", serverInfo.CertConfigPath, err)
		}

		// Сохраняем объединенный файл сертификата и ключа
		combinedCommand := fmt.Sprintf("echo '%s' > %s && chmod 600 %s", combinedContent, combinedPath, combinedPath)
		slog.Info("SaveOnServer: Сохраняем объединенный файл сертификата и ключа")
		output, err = executeSSHCommand(sshClient, combinedCommand)
		if err != nil {
			slog.Error("SaveOnServer: Ошибка сохранения объединенного файла", slog.Any("error", err), slog.String("output", string(output)))
			return fmt.Errorf("failed to save combined certificate and key file: %w", err)
		}

		// Сохраняем промежуточный CA сертификат
		subCACommand := fmt.Sprintf("echo '%s' > %s", subCACert, subCAPath)
		slog.Info("SaveOnServer: Сохраняем промежуточный CA сертификат")
		output, err = executeSSHCommand(sshClient, subCACommand)
		if err != nil {
			slog.Error("SaveOnServer: Ошибка сохранения промежуточного CA", slog.Any("error", err), slog.String("output", string(output)))
			return fmt.Errorf("failed to save intermediate CA certificate: %w", err)
		}

		// Сохраняем корневой CA сертификат
		rootCACommand := fmt.Sprintf("echo '%s' > %s", rootCACert, rootCAPath)
		slog.Info("SaveOnServer: Сохраняем корневой CA сертификат")
		output, err = executeSSHCommand(sshClient, rootCACommand)
		if err != nil {
			slog.Error("SaveOnServer: Ошибка сохранения корневого CA", slog.Any("error", err), slog.String("output", string(output)))
			return fmt.Errorf("failed to save root CA certificate: %w", err)
		}

		// Сохраняем bundle CRL
		bundleCRLCommand := fmt.Sprintf("echo '%s' > %s", bundleCRL, bundlePEMCRLPath)
		slog.Info("SaveOnServer: Сохраняем bundle CRL")
		output, err = executeSSHCommand(sshClient, bundleCRLCommand)
		if err != nil {
			slog.Error("SaveOnServer: Ошибка сохранения bundle CRL", slog.Any("error", err), slog.String("output", string(output)))
			return fmt.Errorf("failed to save bundle CRL: %w", err)
		}

		slog.Info("SaveOnServer: Объединенный файл сертификата и ключа успешно сохранен на удаленном сервере", slog.String("hostname", serverInfo.Hostname), slog.Int("port", serverInfo.Port), slog.String("combinedPath", combinedPath))

	default:
		slog.Warn("SaveOnServer: Тип приложения не поддерживается для сохранения сертификата", slog.String("appType", data.AppType))
	}
	return nil
}

func NewSaveOnServer() SaveOnServerInterface {
	return &saveOnServer{}
}
