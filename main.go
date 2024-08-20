package main

import (
	"fmt"
	"log"

	"github.com/addspin/tlss/crypts"

	models "github.com/addspin/tlss/models"
	routes "github.com/addspin/tlss/routes"
	"github.com/gofiber/fiber/v3"
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
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	// create tables in db
	_, err = db.Exec(models.SchemaAddServer)
	if err != nil {
		log.Println(err.Error())
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

	//---------------------------------------Create a new engine Template
	engine := html.New("./template", ".html")

	//---------------------------------------Pass the engine to the Views
	app := fiber.New(fiber.Config{
		Views: engine,
	})

	routes.Setup(app)

	log.Fatal(app.Listen(":43000"))
}
