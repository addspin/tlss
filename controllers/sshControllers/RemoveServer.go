package sshControllers

import (
	"log/slog"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	"github.com/spf13/viper"
)

func RemoveSSHKey(c fiber.Ctx) error {
	// ---------------------------------------Database inicialization for remove ssh key
	database := viper.GetString("database.path")

	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("Fatal error", "error", err)
	}

	defer db.Close()

	if c.Method() == "POST" {
		data := new(models.SSHKey)

		err := c.Bind().JSON(data)
		if err != nil {
			return c.Status(400).JSON(
				fiber.Map{"status": "error",
					"message": "Cannot parse JSON!",
					"data":    err},
			)
		}

		// удаляем ssh ключ
		dataRemoveCerts := `DELETE FROM ssh_key WHERE id = :id`
		_, err = db.NamedExec(dataRemoveCerts, data)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{
				"status":  "error",
				"message": "Error deleting SSH key: " + err.Error(),
			})
		}

	}
	return c.Render("add_ssh/sshKeyList-tpl", fiber.Map{})
}
