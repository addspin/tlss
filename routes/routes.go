package routes

import (
	Controllers "github.com/addspin/tlss/controllers"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
)

func Setup(app *fiber.App) {

	// app.Use("/*", static.New("static"))
	app.Get("/*", static.New("./static"))
	app.Get("/index", Controllers.Index)
	app.Get("/add_server", Controllers.AddServerControll)
	app.Post("/add_server", Controllers.AddServerControll)
	app.Post("/remove_server", Controllers.RemoveServer)
	app.Get("/add_server/errorAdd", Controllers.AddServerControll)
	app.Get("/add_certs", Controllers.AddCertsControll)
	app.Post("/add_certs", Controllers.AddCertsControll)
	app.Post("/remove_cert", Controllers.RemoveCert)
	app.Post("/revoke_cert", Controllers.RevokeCert) // отзыв сертификата
	app.Get("/cert_list", Controllers.CertListController)
	app.Post("/cert_list", Controllers.CertListController)
	app.Get("/revoke_certs", Controllers.RevokeCertsController)        // Раздел - список сертификатов для отзыва
	app.Get("/cert_list_revoke", Controllers.CertListRevokeController) // Список сертификатов для отзыва находится в RevokeCertsController
	app.Post("/revoke_certs", Controllers.RevokeCertsController)

	app.Post("/rollback_cert", Controllers.RollbackCert) // Откат сертификата
	// app.Get("/crl", Controllers.Crl)

}
