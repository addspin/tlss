package routes

import (
	Controllers "github.com/addspin/tlss/controllers"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
)

func Setup(app *fiber.App) {

	app.Get("/", Controllers.Index)
	// app.Use("/*", static.New("static"))
	app.Get("/*", static.New("./static"))
	app.Get("/add_server", Controllers.AddServerControll)
	app.Post("/add_server", Controllers.AddServerControll)
	app.Post("/remove_server", Controllers.RemoveServer)

}
