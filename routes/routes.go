package routes

import (
	"github.com/addspin/tlss/controllers"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
	"github.com/jmoiron/sqlx"
)

// Setup настраивает маршруты для приложения
func Setup(app *fiber.App, db *sqlx.DB) {

	// app.Use("/*", static.New("static"))
	app.Get("/*", static.New("./static"))
	app.Get("/index", controllers.Index)
	app.Get("/add_server", controllers.AddServerControll)
	app.Post("/add_server", controllers.AddServerControll)
	app.Post("/remove_server", controllers.RemoveServer)
	app.Get("/add_server/errorAdd", controllers.AddServerControll)
	app.Get("/add_certs", controllers.AddCertsControll)
	app.Post("/add_certs", controllers.AddCertsControll)
	app.Post("/remove_cert", controllers.RemoveCert)
	app.Post("/revoke_cert", controllers.RevokeCert) // отзыв сертификата
	app.Get("/cert_list", controllers.CertListController)
	app.Post("/cert_list", controllers.CertListController)
	app.Get("/revoke_certs", controllers.RevokeCertsController)        // Раздел - список сертификатов для отзыва
	app.Get("/cert_list_revoke", controllers.CertListRevokeController) // Список сертификатов для отзыва находится в RevokeCertsController
	app.Post("/revoke_certs", controllers.RevokeCertsController)
	app.Post("/rollback_cert", controllers.RollbackCert) // Откат сертификата

	// API CRL endpoints
	app.Get("/api/v1/crl", controllers.GetCRL)

	// OCSP маршруты
	app.Get("/api/v1/ocsp/*", controllers.HandleOCSP)
	app.Post("/api/v1/ocsp", controllers.HandleOCSP)
}
