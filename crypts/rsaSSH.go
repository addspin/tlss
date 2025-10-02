package crypts

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"strings"

	"github.com/addspin/tlss/models"
	"github.com/addspin/tlss/utils"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
	"golang.org/x/crypto/ssh"
)

// generatePrivateKey creates a RSA Private Key of specified byte size
func GeneratePrivateKey(bitSize int) (*rsa.PrivateKey, error) {
	// Private Key generation
	privateKey, err := rsa.GenerateKey(rand.Reader, bitSize)
	if err != nil {
		return nil, err
	}

	// Validate Private Key
	err = privateKey.Validate()
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// encodePrivateKeyToPEM encodes Private Key from RSA to PEM format
func EncodePrivateKeyToPEM(privateKey *rsa.PrivateKey) []byte {
	// Get ASN.1 DER format
	privDER := x509.MarshalPKCS1PrivateKey(privateKey)

	// pem.Block
	privBlock := pem.Block{
		Type:    "RSA PRIVATE KEY",
		Headers: nil,
		Bytes:   privDER,
	}

	// Private key in PEM format
	privatePEM := pem.EncodeToMemory(&privBlock)

	return privatePEM
}

// generatePublicKey take a rsa.PublicKey and return bytes suitable for writing to .pub file
// returns in the format "ssh-rsa ..."
func GeneratePublicKey(privatekey *rsa.PublicKey) ([]byte, error) {
	publicRsaKey, err := ssh.NewPublicKey(privatekey)
	if err != nil {
		return nil, err
	}

	pubKeyBytes := ssh.MarshalAuthorizedKey(publicRsaKey)

	return pubKeyBytes, nil
}

// - error: an error if there was a problem adding the public key or connecting to the remote server.
func AddAuthorizedKeys(db *sqlx.DB, hostname, tlssSSHport, username, password, path, sshKeyName string) error {

	var key models.SSHKey
	if sshKeyName != "" {
		err := db.Get(&key, "SELECT * FROM ssh_key WHERE server_name = ?", sshKeyName)
		if err != nil {
			return fmt.Errorf("не удалось извлечь сертфиикаты: %w", err)
		}
		aes := Aes{}
		decryptPrivKey, err := aes.Decrypt(([]byte(key.PrivateKey)), AesSecretKey.Key)
		if err != nil {
			log.Fatalf("rsaSSH: ошибка расшифровки приватного ключа %v", err)
		}
		log.Println("decryptPrivKey: ", string(decryptPrivKey))
		signer, err := ssh.ParsePrivateKey(decryptPrivKey)
		if err != nil {
			log.Fatalf("rsaSSH: ошибка, невозможно получить приватный ключ %v", err)
		}
		log.Println("signer: ", signer)
		keyConfig := &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{
				ssh.PublicKeys(signer),
			},
			// HostKeyCallback: ssh.FixedHostKey(parsedPubKey),
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         utils.SelectTime(viper.GetString("add_server.unit"), viper.GetInt("add_server.waitingToConnect")),
		}
		client, err := ssh.Dial("tcp", hostname+":"+tlssSSHport, keyConfig)
		if err != nil {
			log.Println("addServer: ошибка подключения к серверу:", err)
			return fmt.Errorf("ошибка подключения к серверу: %w", err)
		}
		defer client.Close()

		err = testEndCopy(client, hostname, path, key)
		if err != nil {
			return fmt.Errorf("addServer: key:ошибка тестирования пути и копирования ключа: %w", err)
		}
	}
	if password != "" {
		err := db.Get(&key, "SELECT * FROM ssh_key WHERE server_name = ?", "Default")
		if err != nil {
			return fmt.Errorf("не удалось извлечь сертфиикаты: %w", err)
		}
		keyConfig := &ssh.ClientConfig{
			User: username,
			Auth: []ssh.AuthMethod{
				ssh.Password(password),
			},
			// HostKeyCallback: ssh.FixedHostKey(parsedPubKey),
			HostKeyCallback: ssh.InsecureIgnoreHostKey(),
			Timeout:         utils.SelectTime(viper.GetString("add_server.unit"), viper.GetInt("add_server.waitingToConnect")),
		}
		client, err := ssh.Dial("tcp", hostname+":"+tlssSSHport, keyConfig)
		if err != nil {
			log.Println("addServer: ошибка подключения к серверу:", err)
			return fmt.Errorf("ошибка подключения к серверу: %w", err)
		}
		defer client.Close()

		err = testEndCopy(client, hostname, path, key)
		if err != nil {
			return fmt.Errorf("addServer: password: ошибка тестирования пути и копирования ключа: %w", err)
		}
	}
	return nil
}

func testEndCopy(client *ssh.Client, hostname, path string, key models.SSHKey) error {
	TestPathCert, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("addServer: ошибка создания сессии: %w", err)
	}
	defer TestPathCert.Close()

	cmdPathCertTest := "test -d " + path + " || { echo 'Директория " + path + " не существует'; exit 1; }"

	err = TestPathCert.Run(cmdPathCertTest)
	if err != nil {
		return fmt.Errorf("addServer: ошибка, путь хранения сертификата не существует: %w", err)
	}

	sessionTestCert, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("addServer: ошибка создания сессии: %w", err)
	}
	defer sessionTestCert.Close()

	// add cert to authorized_keys
	cmdAddCert := "echo '" + string(key.PublicKey) + "' >> ~/.ssh/authorized_keys"
	// test folder and certs
	pubKey := strings.TrimSpace(string(key.PublicKey))
	// Извлекаем основную часть ключа (тип и ключ без комментария) - первые два поля
	keyParts := strings.Fields(pubKey)
	if len(keyParts) < 2 {
		return fmt.Errorf("addServer: некорректный формат публичного ключа")
	}
	keyCore := keyParts[0] + " " + keyParts[1] // ssh-rsa + base64_key
	// Ищем по основной части ключа, игнорируя комментарий
	cmdTestCert := "mkdir -p ~/.ssh && chmod 0700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 0600 ~/.ssh/authorized_keys && grep -qF '" + keyCore + "' ~/.ssh/authorized_keys 2>/dev/null"

	err = sessionTestCert.Run(cmdTestCert)
	keyExists := (err == nil) // Если команда успешна - ключ найден
	sessionTestCert.Close()

	sessionAddCert, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("addServer: ошибка создания сессии: %w", err)
	}
	defer sessionAddCert.Close()

	if !keyExists {
		err := sessionAddCert.Run(cmdAddCert)
		if err != nil {
			return fmt.Errorf("addServer: ошибка выполнения команды sessionAddCert: %w", err)
		}
		log.Println("rsaSSH: ключ успешно добавлен на сервер ", hostname)
		sessionAddCert.Close()
	} else {
		log.Println("rsaSSH: ключ уже существует, пропускаем добавление на сервер ", hostname)
	}
	return nil
}
