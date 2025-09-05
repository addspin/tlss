package main

import (
	"fmt"
	"log"
	"time"

	"github.com/addspin/tlss/check"
	"github.com/addspin/tlss/crl"
	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/addspin/tlss/routes"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/compress"
	"github.com/gofiber/template/html/v2"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

const savePrivateFileTo string = "id_rsa_tlss"
const savePublicFileTo string = "id_rsa_tlss.pub"
const bitSize int = 4096

func main() {

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	database := viper.GetString("database.path")
	//---------------------------------------Database inicialization
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	log.Println("Connected to database: ", database)
	defer db.Close()

	// create add_server tables in db (хранит данные серверов)
	_, err = db.Exec(models.SchemaServer)
	if err != nil {
		log.Println(err.Error())
	}
	// create SchemaKey tables in db (хранит данные ключа)
	_, err = db.Exec(models.SchemaKey)
	if err != nil {
		log.Println(err.Error())
	}
	// create SchemaCerts tables in db (хранит данные сертификатов)
	_, err = db.Exec(models.SchemaCerts)
	if err != nil {
		log.Println(err.Error())
	}
	// create SchemaRootCAtlss tables in db (хранит данные корневого CA)
	// _, err = db.Exec(models.SchemaRootCAtlss)
	// if err != nil {
	// 	log.Println(err.Error())
	// }
	// // create SchemaSubCAtlss tables in db (хранит данные подчиненного CA используемый для подписания конечных сертификатов)
	// _, err = db.Exec(models.SchemaSubCAtlss)
	// if err != nil {
	// 	log.Println(err.Error())
	// }

	// create SchemaCA tables in db (хранит данные CA)
	_, err = db.Exec(models.SchemaCA)
	if err != nil {
		log.Println(err.Error())
	}

	// create SchemaCrlInfoSubCA tables in db (хранит данные CRL подписанных сертификатами Sub CA)
	_, err = db.Exec(models.SchemaCrlInfoSubCA)
	if err != nil {
		log.Println(err.Error())
	}

	// create SchemaCrlInfoRootCA tables in db (хранит данные CRL подписанных сертификатами Root CA)
	_, err = db.Exec(models.SchemaCrlInfoRootCA)
	if err != nil {
		log.Println(err.Error())
	}

	// create SchemaCRL tables in db (хранит данные CRL)
	_, err = db.Exec(models.SchemaCRL)
	if err != nil {
		log.Println(err.Error())
	}

	// create SchemaCrlInfoUser tables in db (хранит данные CRL user)
	// _, err = db.Exec(models.SchemaCrlInfoUser)
	// if err != nil {
	// 	log.Println(err.Error())
	// }

	// create Users tables in db (хранит данные Users)
	_, err = db.Exec(models.UsersData)
	if err != nil {
		log.Println(err.Error())
	}

	// create SchemaEntity tables in db (хранит данные сущностей)
	_, err = db.Exec(models.SchemaEntity)
	if err != nil {
		log.Println(err.Error())
	}

	// create SchemaOID tables in db (хранит данные OID)
	_, err = db.Exec(models.SchemaOID)
	if err != nil {
		log.Println(err.Error())
	}

	// create SchemaUserCerts tables in db (хранит данные пользовательских сертификатов)
	_, err = db.Exec(models.SchemaUserCerts)
	if err != nil {
		log.Println(err.Error())
	}

	// create SchemaOCSPCertificate tables in db (хранит данные OCSP) отключено подписываем OCSP ответы subCA
	// _, err = db.Exec(models.SchemaOCSPCertificate)
	// if err != nil {
	// 	log.Println(err.Error())
	// }

	// create SchemaOCSPRevoke tables in db (хранит данные об отозванных сертификатах для OCSP)
	_, err = db.Exec(models.SchemaOCSPRevoke)
	if err != nil {
		log.Println(err.Error())
	}

	// create SchemaUserOCSPRevoke tables in db (хранит данные об пользовательских отозванных сертификатах для OCSP)
	_, err = db.Exec(models.SchemaUserOCSPRevoke)
	if err != nil {
		log.Println(err.Error())
	}

	// запрос ввода пароля Временно отключен, добавлен в config.yaml
	// var pwd []byte
	// fmt.Print("Enter password: ")
	// fmt.Scanln(&pwd)
	// //если пароль меньше 16 байт то дополняем его нулями
	// var maxPwd = make([]byte, 16)
	// for len(pwd) < len(maxPwd) {
	// 	pwd = append(pwd, 0)
	// }
	pwd := []byte(viper.GetString("login.password"))

	//проверяем, есть ли в таблице хотя  бы одно значение key
	var exists bool
	err = db.Get(&exists, "SELECT EXISTS (SELECT 1 FROM secret_key)")
	if err != nil {
		log.Fatal(err)
	}
	//если нету то просим ввести ключ
	aes := crypts.Aes{}
	if !exists {
		// запрос на ввод логина
		var login string
		fmt.Print("Enter login: ")
		fmt.Scanln(&login)

		// запрос ввода пароля
		var pwd []byte
		fmt.Print("Enter password: ")
		fmt.Scanln(&pwd)
		//если пароль меньше 16 байт то дополняем его нулями
		var maxPwd = make([]byte, 16)
		for len(pwd) < len(maxPwd) {
			pwd = append(pwd, 0)
		}

		var key []byte
		fmt.Print("Enter key: ")
		fmt.Scanln(&key)
		//если ключ меньше 32 байт то дополняем его нулями
		var maxKey = make([]byte, 32)
		for len(key) < len(maxKey) {
			key = append(key, 0)
		}
		// шифруем ключ паролем
		cryptoKey, err := aes.Encrypt(key, pwd) // cryptoKey - зашифрованный ключ
		if err != nil {
			log.Fatal(err.Error())
		}
		tx := db.MustBegin()
		// записываем в таблицу key зашифрованный ключ
		keyInsert := `INSERT INTO secret_key (key_data) VALUES ($1)`
		_, err = tx.Exec(keyInsert, cryptoKey)
		if err != nil {
			log.Fatal(err.Error())
		}
		// записываем в таблицу login владельца
		loginInsert := `INSERT INTO users (username) VALUES ($1)`
		_, err = tx.Exec(loginInsert, login)
		if err != nil {
			log.Fatal(err.Error())
		}
		err = tx.Commit()
		if err != nil {
			log.Fatal(err.Error())
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
				log.Fatal(err.Error())
			}
			//записываем расшифрованный ключ в переменную
			crypts.AesSecretKey.Key = decryptKey
		}
		// Генерация CA теперь выполняется через эндпоинт Add CA
	}
	// если в базе есть ключ то расшифровываем и передаем в переменную
	var keyData []models.Key
	err = db.Select(&keyData, "SELECT key_data FROM secret_key WHERE id = 1")
	if err != nil {
		return
	}
	for _, keyData := range keyData {
		decryptKey, err := aes.Decrypt([]byte(keyData.Key), pwd)
		if err != nil {
			log.Fatal(err.Error())
		}
		//записываем расшифрованный ключ в переменную
		crypts.AesSecretKey.Key = decryptKey
	}

	//---------------------------------------Generate ssh key pair
	privateKey, err := crypts.GeneratePrivateKey(bitSize)
	if err != nil {
		log.Fatal(err.Error())
	}

	publicKeyBytes, err := crypts.GeneratePublicKey(&privateKey.PublicKey)
	if err != nil {
		log.Fatal(err.Error())
	}

	privateKeyBytes := crypts.EncodePrivateKeyToPEM(privateKey)

	err = crypts.WriteKeyToFile(privateKeyBytes, []byte(publicKeyBytes), savePrivateFileTo, savePublicFileTo)
	if err != nil {
		log.Fatal(err.Error())
	}

	// Извекаем CA из базы данных для использования в разных пакетах
	err = crypts.ExtractCA.ExtractSubCA(db)
	if err != nil {
		log.Fatal(err.Error())
	}
	log.Printf("ExtractCA: промежуточный CA сертификат и ключ успешно извлечены")

	// Генерация CA теперь выполняется через эндпоинт Add CA

	//---------------------------------------Generate  CRL
	// запускаем генерацию CRL для Root CA и Sub CA через заданный интервал времени
	combinedCRLUpdateInterval := time.Duration(viper.GetInt("CAcrl.updateInterval")) * time.Minute
	go crl.StartCombinedCRLGeneration(combinedCRLUpdateInterval, db)

	//---------------------------------------Start OCSP Responder
	// OCSP-респондер работает отдельно от контроллера, обновляя базу данных
	// ocspUpdateInterval := time.Duration(viper.GetInt("ocsp.updateInterval")) * time.Minute
	// go ocsp.StartOCSPResponder(ocspUpdateInterval)

	//---------------------------------------Start User OCSP Responder
	// userOcspUpdateInterval := time.Duration(viper.GetInt("ocspUser.updateInterval")) * time.Minute
	// go ocsp.StartUserOCSPResponder(userOcspUpdateInterval)

	// --------------------------------------Start check server
	checkServerTime := time.Duration(viper.GetInt("checkServer.time")) * time.Second
	// запускаем проверку доступности серверов
	checkTCP := check.StatusCodeTcp{}
	go checkTCP.TCPPortAvailable(checkServerTime)

	//---------------------------------------Check valid certs
	checkValidationTime := time.Duration(viper.GetInt("certsValidation.time")) * time.Minute
	go check.CheckValidCerts(checkValidationTime)

	//---------------------------------------Recreate certs
	recreateCertsTime := time.Duration(viper.GetInt("recreateCerts.time")) * time.Minute
	go check.RecreateCerts(recreateCertsTime)

	//---------------------------------------Create a new engine Template
	engine := html.New("./template", ".html")

	//---------------------------------------Pass the engine to the Views
	app := fiber.New(fiber.Config{
		Views: engine,
	})
	//---------------------------------------Compress response
	app.Use(compress.New(compress.Config{
		Level: compress.LevelBestCompression,
	}))

	// Настраиваем маршруты
	routes.Setup(app)

	// Определяем, использовать ли HTTPS
	if viper.GetString("app.protocol") == "https" {
		// Запуск с TLS (HTTPS)
		certFile := viper.GetString("app.certFile")
		keyFile := viper.GetString("app.keyFile")

		log.Fatal(app.Listen(viper.GetString("app.hostname")+":"+viper.GetString("app.port"), fiber.ListenConfig{
			CertFile:    certFile,
			CertKeyFile: keyFile,
		}))
	} else {
		// Запуск без TLS (HTTP)
		log.Fatal(app.Listen(viper.GetString("app.hostname") + ":" + viper.GetString("app.port")))
	}
}
