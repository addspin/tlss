package estControllers

import (
	"log/slog"
	"time"

	"github.com/addspin/tlss/models"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	"golang.org/x/crypto/bcrypt"
)

type createESTUserReq struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	MaxUses     int    `json:"MaxUses"`
	TTL         int    `json:"TTL"`
	SigningCAId int    `json:"SigningCAId"`
}

// ESTUserController создание пользователя
func ESTUserController(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("ESTUserController: database error", "error", err)
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Database error"})
	}
	defer db.Close()

	if c.Method() == "POST" {
		req := new(createESTUserReq)
		if err := c.Bind().JSON(req); err != nil {
			return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Cannot parse JSON"})
		}

		if req.Username == "" || req.Password == "" {
			return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Username and password are required"})
		}
		if req.TTL <= 0 {
			return c.Status(400).JSON(fiber.Map{"status": "error", "message": "TTL must be greater than 0"})
		}

		if req.MaxUses <= 0 {
			return c.Status(400).JSON(fiber.Map{"status": "error", "message": "MaxUses must be greater than 0"})
		}

		var est_user_exists int
		db.Get(&est_user_exists, "SELECT COUNT(*) FROM est_users WHERE username = ?", req.Username)
		if est_user_exists > 0 {
			return c.Status(400).JSON(fiber.Map{"status": "error", "message": "User with this name already exists"})
		}

		hash, err := bcrypt.GenerateFromPassword([]byte(req.Password), bcrypt.DefaultCost)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Error hashing password"})
		}

		createdAt := time.Now().Format(time.RFC3339)
		expireAt := time.Now().AddDate(0, 0, req.TTL).Format(time.RFC3339)

		_, err = db.Exec(`INSERT INTO est_users
			(username, password_hash, max_uses, user_status, user_create_time, user_expire_time, ttl, days_left, signing_ca_id)
			VALUES (?, ?, ?, 0, ?, ?, ?, ?, ?)`,
			req.Username, string(hash), req.MaxUses, createdAt, expireAt, req.TTL, req.TTL, req.SigningCAId)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Error creating EST user: " + err.Error()})
		}

		slog.Info("ESTUserController: EST user created", "username", req.Username)
		return c.Status(200).JSON(fiber.Map{"status": "success", "message": "EST user created"})
	}

	if c.Method() == "GET" {
		estUserList := []models.ESTUser{}
		db.Select(&estUserList, `SELECT id, username, max_uses, user_status, ttl, days_left, signing_ca_id,
		COALESCE(user_create_time, '') AS user_create_time,
		COALESCE(user_expire_time, '') AS user_expire_time
		FROM est_users ORDER BY id DESC`)

		for i := range estUserList {
			createTime, err := time.Parse(time.RFC3339, estUserList[i].UserCreateTime)
			if err == nil {
				estUserList[i].UserCreateTime = createTime.Format("02.01.2006 15:04:05")
			}
			expireTime, err := time.Parse(time.RFC3339, estUserList[i].UserExpireTime)
			if err == nil {
				estUserList[i].UserExpireTime = expireTime.Format("02.01.2006 15:04:05")
			}
		}

		entityCAList := []models.EntityCAData{}
		db.Select(&entityCAList, "SELECT id, entity_ca_name FROM entity_ca")

		data := fiber.Map{
			"Title":        "Add EST users",
			"estUserList":  estUserList,
			"entityCAList": entityCAList,
		}

		if c.Get("HX-Request") != "" {
			return c.Render("addESTUser-content", data, "")
		}
		return c.Render("est/addESTUser", data)
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// ESTUserListController возвращает список EST пользователей
func ESTUserListController(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Database error"})
	}
	defer db.Close()
	if c.Method() == "GET" {
		estUserList := []models.ESTUser{}
		db.Select(&estUserList, `SELECT id, username, max_uses, user_status, ttl, days_left, signing_ca_id,
		COALESCE(user_create_time, '') AS user_create_time,
		COALESCE(user_expire_time, '') AS user_expire_time
		FROM est_users ORDER BY id DESC`)

		// Преобразуем формат времени из RFC3339 в 02.01.2006 15:04:05
		for i := range estUserList {
			// Парсим время создания сертификата
			createTime, err := time.Parse(time.RFC3339, estUserList[i].UserCreateTime)
			if err == nil {
				estUserList[i].UserCreateTime = createTime.Format("02.01.2006 15:04:05")
			}

			// Парсим время истечения сертификата
			expireTime, err := time.Parse(time.RFC3339, estUserList[i].UserExpireTime)
			if err == nil {
				estUserList[i].UserExpireTime = expireTime.Format("02.01.2006 15:04:05")
			}
		}

		return c.Render("est/estUserList", fiber.Map{"estUserList": estUserList})
	}
	return c.Status(405).JSON(fiber.Map{
		"status":  "error",
		"message": "Method not allowed",
	})
}

// RemoveESTUser удаляет EST пользователя
func RemoveESTUser(c fiber.Ctx) error {
	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Database error"})
	}
	defer db.Close()

	data := new(models.ESTUser)
	if err := c.Bind().JSON(data); err != nil {
		return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Cannot parse JSON"})
	}
	if data.Id == 0 {
		return c.Status(400).JSON(fiber.Map{"status": "error", "message": "Missing ID"})
	}

	_, err = db.Exec("DELETE FROM est_users WHERE id = ?", data.Id)
	if err != nil {
		return c.Status(500).JSON(fiber.Map{"status": "error", "message": "Error deleting user: " + err.Error()})
	}

	slog.Info("RemoveESTUser: EST user deleted", "id", data.Id)

	return c.Render("est/estUserList-tpl", fiber.Map{})
}
