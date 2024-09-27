package controllers

import (
	"fmt"
	"log"

	"github.com/addspin/tlss/crypts"
	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
)

func AddServerControll(c fiber.Ctx) error {
	//---------------------------------------Database inicialization for add server
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Connected to database: ", database)
	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.Data)

		c.Bind().JSON(data)
		log.Println(data.Hostname, data.Username, data.Password, data.TlssSSHport, data.Path)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}
		if data.Hostname == "" || data.Username == "" || data.Password == "" || data.TlssSSHport == "" || data.Path == "" {
			return c.Status(400).JSON(fiber.Map{
				"status":  "error",
				"message": "Missing required fields",
			})
		}

		err = crypts.AddAuthorizedKeys(data.Hostname, data.TlssSSHport, data.Username, data.Password)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": err.Error(),
			})
		} else {

			tx := db.MustBegin()

			dataTest := `SELECT * FROM add_server WHERE hostname = $1`
			t, err := tx.Query(dataTest, data.Hostname)
			if err != nil {
				log.Fatal(err.Error())
			}
			if t.Next() {
				// if values in database exists then udate
				dataInsert := `UPDATE add_server SET cert_config_path = ? WHERE hostname = ?`
				_, err = tx.Exec(dataInsert, data.Path, data.Hostname)
				if err != nil {
					log.Fatal(err.Error())
				}
				tx.Commit()

			} else {
				// else insert new data
				dataInsert := `INSERT INTO add_server (hostname, cert_config_path) VALUES ($1, $2)`
				_, err = tx.Exec(dataInsert, data.Hostname, data.Path)
				if err != nil {
					log.Fatal(err.Error())
				}
				tx.Commit()
			}
		}
	}
	if c.Method() == "GET" {
		// var hostname = []string{}
		type data struct {
			Hostname       string `db:"hostname"`
			CertConfigPath string `db:"cert_config_path"`
		}
		var datas []data
		err := db.Select(&datas, "SELECT hostname, cert_config_path FROM add_server")
		if err != nil {
			log.Fatal(err)
		}
		log.Println(datas)
		return c.Render("add_server/main", fiber.Map{
			"Title": "Hello, World!+",
			"data":  datas,
		})
	}

	return c.Render("add_server/main", fiber.Map{
		"Title": "Hello, World!+",
	})

}
