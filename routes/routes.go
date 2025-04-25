package routes

import (
	"github.com/addspin/tlss/controllers"
	"github.com/addspin/tlss/middleware"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
)

// Setup настраивает маршруты для приложения
func Setup(app *fiber.App) {
	// Apply middleware to all routes
	app.Use(middleware.AuthMiddleware())

	// Public static files
	app.Get("/*", static.New("./static"))

	// Public routes (no auth required)
	app.Get("/index", controllers.Index)
	app.Get("/login", controllers.LoginControll)
	app.Post("/login", controllers.LoginControll)
	app.Get("/", controllers.LoginControll)
	app.Post("/", controllers.LoginControll)

	// API routes (no auth required)
	app.Get("/api/v1/crl", controllers.GetCRL)
	app.Get("/api/v1/ocsp/*", controllers.HandleOCSP)
	app.Post("/api/v1/ocsp", controllers.HandleOCSP)

	// Protected routes (auth required)
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
	app.Get("/logout", controllers.LogoutController)
}
