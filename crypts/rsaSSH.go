package crypts

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log/slog"
	"strings"

	"github.com/addspin/tlss/models"
	"github.com/addspin/tlss/utils"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

// Генерирует приватный ключ RSA
func GeneratePrivateKeyForSSH(bitSize int) (*rsa.PrivateKey, error) {
	// Генерируем приватный ключ
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Проверяем приватный ключ
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// Кодирует приватный ключ RSA в PEM формат
func EncodePrivateKeyToPEMForSSH(privateKey *rsa.PrivateKey) []byte {
	// Получаем ASN.1 DER формат
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block - блок PEM
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Приватный ключ в PEM формате
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// Генерирует публичный ключ RSA
func GeneratePublicKeyForSSH(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	return pubKeyBytes, nil
}

// Генерирует пару ключей ED25519 для SSH
func GenerateED25519SSHKeyPair() (ed25519.PublicKey, ed25519.PrivateKey, error) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ED25519 SSH key pair: %w", err)
	}
	return publicKey, privateKey, nil
}

// Кодирует приватный ключ ED25519 в PEM формат для SSH
func EncodeED25519PrivateKeyToPEMForSSH(privateKey ed25519.PrivateKey) ([]byte, error) {
	privateKeyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode ED25519 private key: %w", err)
	}
	privateKeyPEM := pem.EncodeToMemory(
		&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: privateKeyBytes,
		},
	)
	return privateKeyPEM, nil
}

// Генерирует публичный ключ ED25519 в SSH формате
func GenerateED25519PublicKeyForSSH(publicKey ed25519.PublicKey) ([]byte, error) {
	sshPublicKey, err := ssh.NewPublicKey(publicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to convert ED25519 public key to SSH format: %w", err)
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(sshPublicKey)
	return pubKeyBytes, nil
}

// Добавление ключа доступа на удаленный сервер, через пароль или ключ
func AddAuthorizedKeys(db *sqlx.DB, hostname, tlssSSHport, username, password, path, sshKeyName string) error {

	var key models.SSHKey
	if sshKeyName != "" {
		err := db.Get(&key, "SELECT * FROM ssh_key WHERE name_ssh_key = ?", sshKeyName)
		if err != nil {
			return fmt.Errorf("failed to retrieve certificates: %w", err)
		}
		aes := Aes{}
		decryptPrivKey, err := aes.Decrypt(([]byte(key.PrivateKey)), AesSecretKey.Key)
		if err != nil {
			slog.Error("rsaSSH: Private key decryption error", "error", err)
		}

		signer, err := ssh.ParsePrivateKey(decryptPrivKey)
		if err != nil {
			slog.Error("rsaSSH: Unable to get private key", "error", err)
		}
		// Используем ключ для подключения к серверу
		keyConfig := &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
			},

			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         utils.SelectTime(viper.GetString("add_server.unit"), viper.GetInt("add_server.waitingToConnect")),
		}
		client, err := ssh.Dial("tcp", hostname+":"+tlssSSHport, keyConfig)
		if err != nil {
			slog.Error("addServer: Server connection error", "error", err)
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer client.Close()

		err = testEndCopy(client, hostname, path, key)
		if err != nil {
			return fmt.Errorf("addServer: key: failed to test path and copy key: %w", err)
		}
	}
	if password != "" {
		err := db.Get(&key, "SELECT * FROM ssh_key WHERE name_ssh_key = ?", "Default")
		if err != nil {
			return fmt.Errorf("failed to retrieve certificates: %w", err)
		}
		keyConfig := &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},

			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         utils.SelectTime(viper.GetString("add_server.unit"), viper.GetInt("add_server.waitingToConnect")),
		}
		client, err := ssh.Dial("tcp", hostname+":"+tlssSSHport, keyConfig)
		if err != nil {
			slog.Error("addServer: Server connection error", "error", err)
			return fmt.Errorf("failed to connect to server: %w", err)
		}
		defer client.Close()

		err = testEndCopy(client, hostname, path, key)
		if err != nil {
			return fmt.Errorf("addServer: password: failed to test path and copy key: %w", err)
		}
	}
	return nil
}

func testEndCopy(client *ssh.Client, hostname, path string, key models.SSHKey) error {
	TestPathCert, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("addServer: failed to create session: %w", err)
	}
	defer TestPathCert.Close()

	cmdPathCertTest := "test -d " + path + " || { echo 'Директория " + path + " не существует'; exit 1; }"

	err = TestPathCert.Run(cmdPathCertTest)
	if err != nil {
		return fmt.Errorf("addServer: certificate storage path does not exist: %w", err)
	}

	sessionTestCert, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("addServer: failed to create session: %w", err)
	}
	defer sessionTestCert.Close()

	// Добавляем ключ в authorized_keys
	cmdAddCert := "echo '" + string(key.PublicKey) + "' >> ~/.ssh/authorized_keys"
	// Тестируем директорию и ключи
	pubKey := strings.TrimSpace(string(key.PublicKey))
	// Извлекаем основную часть ключа (тип и ключ без комментария) - первые два поля
	keyParts := strings.Fields(pubKey)
	if len(keyParts) < 2 {
		return fmt.Errorf("addServer: invalid public key format")
	}
	keyCore := keyParts[0] + " " + keyParts[1] // ssh-rsa + base64_key
	// Ищем по основной части ключа, игнорируя комментарий
	cmdTestCert := "mkdir -p ~/.ssh && chmod 0700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 0600 ~/.ssh/authorized_keys && grep -qF '" + keyCore + "' ~/.ssh/authorized_keys 2>/dev/null"

	err = sessionTestCert.Run(cmdTestCert)
	keyExists := (err == nil) // Если команда успешна - ключ найден
	sessionTestCert.Close()

	sessionAddCert, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("addServer: failed to create session: %w", err)
	}
	defer sessionAddCert.Close()

	if !keyExists {
		err := sessionAddCert.Run(cmdAddCert)
		if err != nil {
			return fmt.Errorf("addServer: failed to execute sessionAddCert command: %w", err)
		}
		slog.Info("rsaSSH: Key successfully added to server", "hostname", hostname)
		sessionAddCert.Close()
	} else {
		slog.Info("rsaSSH: Key already exists, skipping addition to server", "hostname", hostname)
	}
	return nil
}
