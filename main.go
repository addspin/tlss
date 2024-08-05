package main

import (
	"fmt"
	"log"

	"github.com/addspin/models/addServerModel"

	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/gofiber/template/html/v2"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func main() {

	viper.SetConfigName("config")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")

	err := viper.ReadInConfig()
	if err != nil {
		log.Fatalf("Error reading config file: %s", err)
	}

	database := viper.GetString("database.path")

	// Database inicialization
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	db.MustExec(addServerModel.Schema)

	// Create tables server-connected
	// _, err = db.Exec("CREATE TABLE IF NOT EXISTS server_connected (id INTEGER PRIMARY KEY AUTOINCREMENT, hostname TEXT, cert_config_path TEXT, cert_ca_name TEXT, cert_name TEXT)")
	// if err != nil {
	// 	log.Fatal(err)

	// }

	// Create a new engine Template
	engine := html.New("./template", ".html")

	// Pass the engine to the Views
	app := fiber.New(fiber.Config{
		Views: engine,
	})
	app.Get("/*", static.New("static"))

	app.Get("/", func(c fiber.Ctx) error {
		return c.Render("index", fiber.Map{
			"Title": "Hello, World!",
		})
	})

	app.Get("/add_server", func(c fiber.Ctx) error {
		return c.Render("add_server/main", fiber.Map{
			"Title": "Hello, World!",
		})
	})

	app.Get("/add_server", func(c fiber.Ctx) error {
		return c.Render("add_server/main", fiber.Map{
			"Title": "Hello, World!",
		})
	})

	app.Post("/api/add_server", func(c fiber.Ctx) error {
		return c.SendString("I'm a POST request!")
	})

	// app.Get("/add_server", func(c fiber.Ctx) error {
	// 	return c.SendString("Hello, World!")
	// })
	log.Fatal(app.Listen(":3000"))
}
