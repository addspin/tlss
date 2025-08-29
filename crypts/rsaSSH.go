package crypts

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

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

func TestFileCertsSSHTLSS(privCert, pubCert string) (bool, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return false, err
	}
	sshDir := filepath.Join(home, ".ssh")

	files, err := os.ReadDir(sshDir)
	if err != nil {
		log.Fatal(err)
	}
	var privFiles int
	var pubFiles int
	for _, file := range files {
		if file.Name() == privCert {
			privFiles++
		}
		if file.Name() == pubCert {
			pubFiles++
		}
	}
	if privFiles == 0 && pubFiles > 0 {
		err := os.Remove(filepath.Join(sshDir, pubCert))
		if err != nil {
			return false, err
		}
		pubFiles = 0
	}
	if privFiles > 0 && pubFiles == 0 {
		err := os.Remove(filepath.Join(sshDir, privCert))
		if err != nil {
			return false, err
		}
		privFiles = 0
	}
	if privFiles == 0 && pubFiles == 0 {
		log.Println("All TLSS certificates for SSH - created")
		return true, err
	}
	log.Println("All TLSS certificates for SSH - already exist")
	return false, err

}

// writePemToFile writes keys to a file
func WriteKeyToFile(keyBytesPriv, keyBytesPub []byte, saveFileToPriv, saveFileToPub string) error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	sshDir := filepath.Join(home, ".ssh")
	err = os.MkdirAll(sshDir, 0700)
	if err != nil {
		return err
	}

	ok, err := TestFileCertsSSHTLSS(saveFileToPriv, saveFileToPub)
	if err != nil {
		return err
	}
	if ok {
		// Create private certificate
		filePriv, err := os.OpenFile(filepath.Join(sshDir, saveFileToPriv), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer filePriv.Close()

		_, err = io.Copy(filePriv, bytes.NewReader(keyBytesPriv))
		if err != nil {
			return err
		}

		// Create public certificate
		filePub, err := os.OpenFile(filepath.Join(sshDir, saveFileToPub), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			return err
		}
		defer filePub.Close()

		_, err = io.Copy(filePub, bytes.NewReader(keyBytesPub))
		if err != nil {
			return err
		}

	}
	return nil
}

// AddAuthorizedKeys adds a public key to the authorized_keys file on a remote server.
//
// Parameters:
//
// - Hostname: the hostname or IP address of the remote server.
//
// - tlssSSHport: the SSH port number on the remote server.
//
// - username: the username to authenticate with on the remote server.
//
// - password: the password to authenticate with on the remote server.
//
// Returns:
//
// - error: an error if there was a problem adding the public key or connecting to the remote server.
func AddAuthorizedKeys(hostname, tlssSSHport, username, password, path string) error {
	// var hostKey ssh.PublicKey

	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}

	sshDir := filepath.Join(home, ".ssh")

	pubKey, err := os.ReadFile(filepath.Join(sshDir, "id_rsa_tlss.pub"))
	if err != nil {
		return err
	}
	// parsedPubKey, _, _, _, err := ssh.ParseAuthorizedKey(pubKey)
	// if err != nil {
	// 	return err
	// }
	config := &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.Password(password),
		},
		// HostKeyCallback: ssh.FixedHostKey(parsedPubKey),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         time.Duration(viper.GetInt("add_server.waitingToConnect")) * time.Second,
	}
	client, err := ssh.Dial("tcp", hostname+":"+tlssSSHport, config)
	if err != nil {
		log.Println("addServer: ошибка подключения к серверу:", err)
		return fmt.Errorf("ошибка подключения к серверу: %w", err)
	}
	defer client.Close()

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
	cmdAddCert := "echo '" + string(pubKey) + "' >> ~/.ssh/authorized_keys"
	// test folder and certs
	cmdTestCert := "mkdir -p ~/.ssh && chmod 0700 ~/.ssh && touch ~/.ssh/authorized_keys && chmod 0700 ~/.ssh/authorized_keys && awk -v var='" + string(pubKey) + "' 'NF>0 && /.*'${var}'.*/ {print $0}'  ~/.ssh/authorized_keys | wc -l"

	output, err := sessionTestCert.CombinedOutput(cmdTestCert)
	if err != nil {
		return fmt.Errorf("addServer: ошибка выполнения команды sessionTestCert: %w", err)
	}
	sessionTestCert.Close()

	// log.Println(string(output))
	outputString := string(output)
	outputString = strings.TrimSpace(outputString)
	sessionAddCert, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("addServer: ошибка создания сессии: %w", err)
	}
	defer sessionAddCert.Close()

	if outputString == "0" {
		err := sessionAddCert.Run(cmdAddCert)
		if err != nil {
			return fmt.Errorf("addServer: ошибка выполнения команды sessionAddCert: %w", err)
		}
		sessionAddCert.Close()
	}

	return nil
}
