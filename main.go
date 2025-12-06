package main

import (
	"crypto/rand"
	"crypto/x509"
	"embed"
	"encoding/pem"
	"fmt"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/addspin/tlss/check"
	"github.com/addspin/tlss/crl"
	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/addspin/tlss/routes"
	"github.com/addspin/tlss/utils"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/compress"
	"github.com/gofiber/template/html/v2"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

//go:embed template
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

//go:embed configInit.yaml
var defaultConfigInit []byte

const bitSize int = 4096

func main() {
	//  Создаем первичный конфигурационный файл config.yaml из configInit.yaml
	execPath, err := os.Executable()
	if err != nil {
		slog.Error("Cannot determine executable path", "error", err)
		os.Exit(1)
	}
	execDir := filepath.Dir(execPath)
	configPath := filepath.Join(execDir, "config.yaml")
	if _, statErr := os.Stat(configPath); os.IsNotExist(statErr) {
		if writeErr := os.WriteFile(configPath, defaultConfigInit, 0644); writeErr != nil {
			slog.Error("Cannot write default config.yaml", "path", configPath, "error", writeErr)
			os.Exit(1)
		}
		slog.Info("Default config.yaml created", "path", configPath)
	}

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	// Читаем конфиг
	viper.AddConfigPath(".")
	viper.AddConfigPath(execDir)

	err = viper.ReadInConfig()
	if err != nil {
		slog.Error("Error reading config file", "error", err)
		os.Exit(1)
	}

	// Настраиваем структурированное логирование
	logFile, err := utils.SetupSlogLogger()
	if err != nil {
		slog.Error("Error setting up logging", "error", err)
		// Продолжаем со стандартным логированием
	}
	if logFile != nil {
		defer logFile.Close()
	}

	database := viper.GetString("database.path")
	//---------------------------------------Database initialization
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Database connection error", "error", err)
		os.Exit(1)
	}
	slog.Info("Database connection successful", "database", database)
	defer db.Close()

	// init
	// Создание необходимых директорий если они не существуют
	dirs := []string{"db", "root_ca_tlss", "https", "crlFile", "logs"}
	for _, dir := range dirs {
		err := os.MkdirAll(dir, 0755)
		if err != nil {
			slog.Error("Error creating directory", "directory", dir, "error", err)
		} else {
			slog.Debug("Directory created or already exists", "directory", dir)
		}
	}

	// create add_server tables in db (хранит данные серверов)
	_, err = db.Exec(models.SchemaServer)
	if err != nil {
		slog.Error("Error creating server table", "error", err)
	}
	// create SchemaKey tables in db (хранит данные ключа)
	_, err = db.Exec(models.SchemaKey)
	if err != nil {
		slog.Error("Error creating key table", "error", err)
	}
	// create SchemaCerts tables in db (хранит данные сертификатов)
	_, err = db.Exec(models.SchemaCerts)
	if err != nil {
		slog.Error("Error creating certs table", "error", err)
	}

	// create SchemaCA tables in db (хранит данные CA)
	_, err = db.Exec(models.SchemaCA)
	if err != nil {
		slog.Error("Error creating CA table", "error", err)
	}

	// create SchemaCrlInfoSubCA tables in db (хранит данные CRL подписанных сертификатами Sub CA)
	_, err = db.Exec(models.SchemaCrlInfoSubCA)
	if err != nil {
		slog.Error("Error creating CRL info SubCA table", "error", err)
	}

	// create SchemaCrlInfoRootCA tables in db (хранит данные CRL подписанных сертификатами Root CA)
	_, err = db.Exec(models.SchemaCrlInfoRootCA)
	if err != nil {
		slog.Error("Error creating CRL info RootCA table", "error", err)
	}

	// create SchemaCRL tables in db (хранит данные CRL)
	_, err = db.Exec(models.SchemaCRL)
	if err != nil {
		slog.Error("Error creating CRL table", "error", err)
	}

	// create SchemaSSHKey tables in db (хранит данные ssh ключей)
	_, err = db.Exec(models.SchemaSSHKey)
	if err != nil {
		slog.Error("Error creating SSH key table", "error", err)
	}

	// create Users tables in db (хранит данные Users)
	_, err = db.Exec(models.UsersData)
	if err != nil {
		slog.Error("Error creating users table", "error", err)
	}

	// create SchemaEntity tables in db (хранит данные сущностей)
	_, err = db.Exec(models.SchemaEntity)
	if err != nil {
		slog.Error("Error creating entity table", "error", err)
	}

	// create SchemaEntityCA tables in db (хранит данные сущностей для внешних CA)
	_, err = db.Exec(models.SchemaEntityCA)
	if err != nil {
		slog.Error("Error creating entity CA table", "error", err)
	}

	// create SchemaOID tables in db (хранит данные OID)
	_, err = db.Exec(models.SchemaOID)
	if err != nil {
		slog.Error("Error creating OID table", "error", err)
	}

	// create SchemaUserCerts tables in db (хранит данные пользовательских сертификатов)
	_, err = db.Exec(models.SchemaUserCerts)
	if err != nil {
		slog.Error("Error creating user certs table", "error", err)
	}
	var password, salt []byte
	var login string

	//проверяем, есть ли в таблице хотя-бы одно значение ключа
	var exists bool
	err = db.Get(&exists, "SELECT EXISTS (SELECT 1 FROM secret_key)")
	if err != nil {
		slog.Error("Error checking if secret key exists", "error", err)
		os.Exit(1)
	}
	//если в базе нет ключа, то просим ввести ключ
	aes := crypts.Aes{}
	if !exists {
		// если данные авторизации берутся из конфига, то проверяем, что они не пустые
		if viper.GetBool("login.authConfig") {
			login = viper.GetString("login.username")
			if login == "" {
				slog.Error("Login cannot be empty")
				os.Exit(1)
			}
			password = []byte(viper.GetString("login.password"))
			if len(password) == 0 {
				slog.Error("Password cannot be empty")
				os.Exit(1)
			}
			salt = []byte(viper.GetString("login.salt"))
			if len(salt) == 0 {
				slog.Error("Salt cannot be empty")
				os.Exit(1)
			}
		} else {
			// Init-ввод при первом старте
			fmt.Print("Init Login: ")
			_, err = fmt.Scanln(&login)
			if err != nil {
				slog.Error("Error reading login", "error", err)
				os.Exit(1)
			}
			fmt.Print("Init password: ")
			_, err = fmt.Scanln(&password)
			if err != nil {
				slog.Error("Error reading password", "error", err)
				os.Exit(1)
			}
			fmt.Print("Init salt: ")
			_, err = fmt.Scanln(&salt)
			if err != nil {
				slog.Error("Error reading salt", "error", err)
				os.Exit(1)
			}
			if len(password) == 0 || len(salt) == 0 {
				slog.Error("Password and salt cannot be empty")
				os.Exit(1)
			}
		}

		// Генерируем итоговый пароль через PBKDF2
		p := crypts.PWD{}
		pwd := p.CreatePWDKeyFromUserInput(password, salt)

		// генерируем случайный ключ
		key := make([]byte, 32)
		_, err := rand.Read(key)
		if err != nil {
			slog.Error("Error generating random key", "error", err)
			os.Exit(1)
		}
		// шифруем ключ паролем
		cryptoKey, err := aes.Encrypt(key, pwd) // cryptoKey - зашифрованный ключ
		if err != nil {
			slog.Error("Fatal error", "error", err)
			os.Exit(1)
		}
		tx := db.MustBegin()
		// записываем в таблицу key зашифрованный ключ
		keyInsert := `INSERT INTO secret_key (key_data) VALUES ($1)`
		_, err = tx.Exec(keyInsert, cryptoKey)
		if err != nil {
			slog.Error("Error inserting secret key", "error", err)
			os.Exit(1)
		}
		// записываем в таблицу login владельца (избегаем дубликатов)
		loginInsert := `INSERT OR IGNORE INTO users (username) VALUES ($1)`
		_, err = tx.Exec(loginInsert, login)
		if err != nil {
			slog.Error("Error inserting user", "error", err)
			os.Exit(1)
		}
		err = tx.Commit()
		if err != nil {
			slog.Error("Error committing transaction", "error", err)
			os.Exit(1)
		}
		//расшифровываем и передаем в переменную ключ
		var keyData []models.Key
		err = db.Select(&keyData, "SELECT key_data FROM secret_key WHERE id = 1")
		if err != nil {
			return
		}
		for _, keyData := range keyData {
			decryptKey, err := aes.Decrypt([]byte(keyData.Key), pwd)
			if err != nil {
				slog.Error("Error decrypting key", "error", err)
				os.Exit(1)
			}
			//записываем расшифрованный ключ в переменную
			crypts.AesSecretKey.Key = decryptKey
		}
	}

	// если в базе есть ключ, то получаем логин/пароль/соль для расшифровки ключа
	if exists {
		// если данные авторизации берутся из конфига, то проверяем, что они не пустые
		if viper.GetBool("login.authConfig") {
			login = viper.GetString("login.username")
			if login == "" {
				slog.Error("Login cannot be empty")
				os.Exit(1)
			}
			password = []byte(viper.GetString("login.password"))
			if len(password) == 0 {
				slog.Error("Password cannot be empty")
				os.Exit(1)
			}
			salt = []byte(viper.GetString("login.salt"))
			if len(salt) == 0 {
				slog.Error("Salt cannot be empty")
				os.Exit(1)
			}
			// проверяем, что пользователь существует в БД
			var userCount int
			err = db.Get(&userCount, "SELECT COUNT(1) FROM users WHERE username = ?", login)
			if err != nil {
				slog.Error("Error checking user existence", "error", err)
				os.Exit(1)
			}
			if userCount == 0 {
				slog.Error("Login not found")
				os.Exit(1)
			}
		} else {
			fmt.Print("Enter Login: ")
			_, err = fmt.Scanln(&login)
			if err != nil {
				slog.Error("Error reading login", "error", err)
				os.Exit(1)
			}
			if len(login) == 0 {
				slog.Error("Login cannot be empty")
				os.Exit(1)
			}
			// проверяем, что пользователь существует в БД
			var userCount int
			err = db.Get(&userCount, "SELECT COUNT(1) FROM users WHERE username = ?", login)
			if err != nil {
				slog.Error("Error checking user existence", "error", err)
				os.Exit(1)
			}
			if userCount == 0 {
				slog.Error("Login not found")
				os.Exit(1)
			}
			fmt.Print("Enter password: ")
			_, err = fmt.Scanln(&password)
			if err != nil {
				slog.Error("Error reading password", "error", err)
				os.Exit(1)
			}
			if len(password) == 0 {
				slog.Error("Password cannot be empty")
				os.Exit(1)
			}
			fmt.Print("Enter salt: ")
			_, err = fmt.Scanln(&salt)
			if err != nil {
				slog.Error("Error reading salt", "error", err)
				os.Exit(1)
			}
			if len(salt) == 0 {
				slog.Error("Salt cannot be empty")
				os.Exit(1)
			}
		}
	}

	// Генерируем итоговый пароль через PBKDF2
	p := crypts.PWD{}
	pwd := p.CreatePWDKeyFromUserInput(password, salt)

	var keyData []models.Key
	err = db.Select(&keyData, "SELECT key_data FROM secret_key WHERE id = 1")
	if err != nil {
		return
	}
	for _, keyData := range keyData {
		decryptKey, err := aes.Decrypt([]byte(keyData.Key), pwd)
		if err != nil {
			slog.Error("Error decrypting key", "error", err)
			os.Exit(1)
		}
		//записываем расшифрованный ключ в переменную
		crypts.AesSecretKey.Key = decryptKey
	}

	//---------------------------------------Генерируем Default ssh key для подключения к серверам
	var testKey models.SSHKey
	err = db.Get(&testKey, "SELECT * FROM ssh_key WHERE name_ssh_key = ?", "Default")
	if err != nil {
		privateKey, err := crypts.GeneratePrivateKeyForSSH(bitSize)
		if err != nil {
			slog.Error("Fatal error", "error", err)
			os.Exit(1)
		}

		keyPEM := pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKey),
		})
		// privateKeyBytes := crypts.EncodePrivateKeyToPEM(privateKey)

		publicKeyBytes, err := crypts.GeneratePublicKeyForSSH(&privateKey.PublicKey)
		if err != nil {
			slog.Error("Fatal error", "error", err)
			os.Exit(1)
		}

		// privateKeyBytes := crypts.EncodePrivateKeyToPEM(privateKey)
		encryptedKey, err := aes.Encrypt(keyPEM, crypts.AesSecretKey.Key)
		if err != nil {
			slog.Error("Fatal error", "error", err)
			os.Exit(1)
		}
		// Если записи нет, вставляем новую
		_, err = db.Exec("INSERT INTO ssh_key (name_ssh_key, public_key, private_key, key_length, algorithm) VALUES (?, ?, ?, ?, ?)", "Default", string(publicKeyBytes), string(encryptedKey), bitSize, "RSA")
		if err != nil {
			slog.Error("Fatal error", "error", err)
			os.Exit(1)
		}

	}

	// Извлекаем CA из базы данных для использования в разных пакетах
	err = crypts.ExtractCA.ExtractSubCA(db)
	if err != nil {
		slog.Error("Error occurred", "error", err)
	} else {
		slog.Info("ExtractCA: Intermediate CA certificate and key successfully extracted")
	}

	//---------------------------------------Start Monitor
	TCPInterval := utils.SelectTime(viper.GetString("monitor.unitTCP"), viper.GetInt("monitor.TCPInterval"))
	RecreateCertsInterval := utils.SelectTime(viper.GetString("recreateCerts.unit"), viper.GetInt("recreateCerts.recreateCertsInterval"))
	CheckValidCertsInterval := utils.SelectTime(viper.GetString("certsValidation.unit"), viper.GetInt("certsValidation.certsValidationInterval"))
	go check.Monitore(TCPInterval, RecreateCertsInterval, CheckValidCertsInterval)

	//---------------------------------------Start Generate  Root and Sub CRL
	combinedCRLUpdateInterval := utils.SelectTime(viper.GetString("CAcrl.unit"), viper.GetInt("CAcrl.updateInterval"))
	go crl.StartCombinedCRLGeneration(combinedCRLUpdateInterval, db)

	// --------------------------------------Start check server
	serverInterval := utils.SelectTime(viper.GetString("checkServer.unit"), viper.GetInt("checkServer.checkServerInterval"))
	checkTCP := check.StatusCodeTcp{}
	go checkTCP.TCPPortAvailable(serverInterval)

	//---------------------------------------Start Check valid certs
	validationInterval := utils.SelectTime(viper.GetString("certsValidation.unit"), viper.GetInt("certsValidation.certsValidationInterval"))
	go check.CheckValidCerts(validationInterval)

	//---------------------------------------Start Recreate certs
	recreateCertsInterval := utils.SelectTime(viper.GetString("recreateCerts.unit"), viper.GetInt("recreateCerts.recreateCertsInterval"))
	go check.RecreateCerts(recreateCertsInterval)

	//---------------------------------------Create a new engine Template
	// Создаем поддиректорию для шаблонов
	templateFiles, err := fs.Sub(templateFS, "template")
	if err != nil {
		slog.Error("Error creating filesystem for templates", "error", err)
		os.Exit(1)
	}

	// Инициализируем движок шаблонов с встроенными файлами
	engine := html.NewFileSystem(http.FS(templateFiles), ".html")

	//---------------------------------------Pass the engine to the Views
	app := fiber.New(fiber.Config{
		Views: engine,
	})
	//---------------------------------------Compress response
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestCompression,
	}))

	// Настраиваем маршруты
	routes.Setup(app, staticFS)

	// Определяем, использовать ли HTTPS
	if viper.GetString("app.protocol") == "https" {
		// Запуск с TLS (HTTPS)
		certFile := viper.GetString("app.certFile")
		keyFile := viper.GetString("app.keyFile")
		address := viper.GetString("app.hostname") + ":" + viper.GetString("app.port")

		slog.Info("Starting TLSS server with HTTPS",
			"address", address,
			"cert_file", certFile,
			"key_file", keyFile)

		if err := app.Listen(address, fiber.ListenConfig{
			CertFile:    certFile,
			CertKeyFile: keyFile,
		}); err != nil {
			slog.Error("Error starting HTTPS server", "error", err)
			os.Exit(1)
		}
	} else {
		// Запуск без TLS (HTTP)
		address := viper.GetString("app.hostname") + ":" + viper.GetString("app.port")

		slog.Info("Starting TLSS server with HTTP", "address", address)

		if err := app.Listen(address); err != nil {
			slog.Error("Error starting HTTP server", "error", err)
			os.Exit(1)
		}
	}
}
