package routes

import (
	"embed"
	"io/fs"

	"github.com/addspin/tlss/controllers"
	caControllers "github.com/addspin/tlss/controllers/caControllers"
	usersCertControllers "github.com/addspin/tlss/controllers/usersCertControllers"
	"github.com/addspin/tlss/middleware"
	"github.com/gofiber/fiber/v3"
	"github.com/gofiber/fiber/v3/middleware/static"
)

// Setup настраивает маршруты для приложения
func Setup(app *fiber.App, staticFS embed.FS) {
	// Apply middleware to all routes
	app.Use(middleware.AuthMiddleware())

	// Public static files
	staticSub, err := fs.Sub(staticFS, "static")
	if err != nil {
		panic(err)
	}

	// Основной маршрут для статических файлов
	app.Use("/static", static.New("", static.Config{
		FS: staticSub,
	}))

	// Дополнительные маршруты для обратной совместимости
	// app.Use("/css", static.New("css", static.Config{
	// 	FS: staticSub,
	// }))
	// app.Use("/js", static.New("js", static.Config{
	// 	FS: staticSub,
	// }))
	// app.Use("/fonts", static.New("fonts", static.Config{
	// 	FS: staticSub,
	// }))
	// app.Use("/svg", static.New("svg", static.Config{
	// 	FS: staticSub,
	// }))

	// Public routes (no auth required)
	app.Get("/overview", controllers.Overview)
	app.Get("/login", controllers.LoginControll)
	app.Post("/login", controllers.LoginControll)
	app.Get("/", controllers.LoginControll)
	app.Post("/", controllers.LoginControll)

	// API routes (no auth required)
	app.Get("/api/v1/crl/subca/der", controllers.GetSubCACRL)       // Получение Sub CA CRL в DER формате
	app.Get("/api/v1/crl/rootca/der", controllers.GetRootCACRL)     // Получение Root CA CRL в DER формате
	app.Get("/api/v1/crl/bundleca/der", controllers.GetBundleCACRL) // Получение бандла Root CA и Sub CA CRL в DER формате

	app.Get("/api/v1/crl/subca/pem", controllers.GetSubCAPemCRL)       // Получение Sub CA CRL в PEM формате
	app.Get("/api/v1/crl/rootca/pem", controllers.GetRootCAPemCRL)     // Получение Root CA CRL в PEM формате
	app.Get("/api/v1/crl/bundleca/pem", controllers.GetBundleCAPemCRL) // Получение бандла Root CA и Sub CA CRL в PEM 	формате

	// Admin API routes (auth required)
	app.Post("/api/v1/crl/bundleca/generate", controllers.GenerateCombinedCACRL) // Генерация бандла Root CA и Sub CA через API

	// Protected routes (auth required)
	app.Get("/add_server", controllers.AddServerControll)                 // Получение списка серверов
	app.Post("/add_server", controllers.AddServerControll)                // Добавление сервера
	app.Get("/server_list", controllers.ServerListController)             // Получение списка серверов
	app.Get("/add_server_entity", controllers.AddServerEntityController)  // Получение списка сущностей для серверных сертификатов
	app.Post("/add_server_entity", controllers.AddServerEntityController) // Добавление сущности для серверных сертификатов
	app.Post("/remove_server", controllers.RemoveServer)
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
	app.Get("/take_cert", controllers.TakeCert)          // Скачать сертификат

	app.Get("/add_entity", usersCertControllers.AddEntityController)               // Получение сущности
	app.Post("/add_entity", usersCertControllers.AddEntityController)              // Добавление сущности
	app.Get("/add_oid", usersCertControllers.AddOIDController)                     // Получение списка OID
	app.Post("/add_oid", usersCertControllers.AddOIDController)                    // Добавление OID
	app.Post("/remove_oid", usersCertControllers.RemoveOID)                        // Удаление OID
	app.Post("/remove_entity", usersCertControllers.RemoveEntity)                  // Удаление сущности
	app.Get("/add_users_certs", usersCertControllers.AddUserCertsController)       // Получение списка сертификатов пользователей
	app.Post("/add_users_certs", usersCertControllers.AddUserCertsController)      // Добавление сертификата пользователя
	app.Get("/revoke_users_certs", usersCertControllers.RevokeUserCertsController) // Получение списка сертификатов для отзыва
	app.Post("/remove_users_cert", usersCertControllers.RemoveUserCert)
	app.Post("/revoke_users_cert", usersCertControllers.RevokeUserCert)
	app.Get("/user_cert_list_revoke", usersCertControllers.UserCertListRevokeController) // Получение списка сертификатов для отзыва
	app.Get("/user_cert_list", usersCertControllers.UserCertListController)              // Получение списка сертификатов пользователей
	app.Post("/user_cert_list", usersCertControllers.UserCertListController)
	app.Post("/rollback_users_cert", usersCertControllers.RollbackUserCert)

	app.Get("/add_ca", caControllers.AddCAController)                  // Получение списка CA
	app.Post("/add_ca", caControllers.AddCAController)                 // Добавление CA
	app.Get("/ca_list", caControllers.CACertListController)            // Получение списка CA
	app.Post("/revoke_ca_certs", caControllers.RevokeCACert)           // Отзыв CA
	app.Post("/remove_ca_cert", caControllers.RemoveCACert)            // Удаление CA
	app.Get("/revoke_ca_certs", caControllers.RevokeCACertsController) // Получение списка CA для отзыва

	app.Get("/logout", controllers.LogoutController)
}
