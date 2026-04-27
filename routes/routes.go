package routes

import (
	"embed"
	"io/fs"

	apiKeyControllers "github.com/addspin/tlss/controllers/apiKeyControllers"
	caControllers "github.com/addspin/tlss/controllers/caControllers"
	certInfoController "github.com/addspin/tlss/controllers/certInfoController"
	loginControllers "github.com/addspin/tlss/controllers/loginControllers"
	overviewController "github.com/addspin/tlss/controllers/overviewController"
	serverCertControllers "github.com/addspin/tlss/controllers/serverCertControllers"
	sshControllers "github.com/addspin/tlss/controllers/sshControllers"
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

	// Public routes (no auth required)
	app.Get("/overview", overviewController.Overview)
	app.Get("/login", loginControllers.LoginControll)
	app.Post("/login", loginControllers.LoginControll)
	app.Get("/", loginControllers.LoginControll)
	app.Post("/", loginControllers.LoginControll)

	// CRL read endpoints — публичные, без авторизации
	app.Get("/api/v1/crl/subca/der", serverCertControllers.GetSubCACRL)
	app.Get("/api/v1/crl/rootca/der", serverCertControllers.GetRootCACRL)
	app.Get("/api/v1/crl/bundleca/der", serverCertControllers.GetBundleCACRL)
	app.Get("/api/v1/crl/subca/pem", serverCertControllers.GetSubCAPemCRL)
	app.Get("/api/v1/crl/rootca/pem", serverCertControllers.GetRootCAPemCRL)
	app.Get("/api/v1/crl/bundleca/pem", serverCertControllers.GetBundleCAPemCRL)

	// Admin API endpoints — защищены API ключами с проверкой scope
	app.Post("/api/v1/crl/bundleca/generate", middleware.APIKeyAuth("crl:write"), serverCertControllers.GenerateCombinedCACRL)

	// Protected routes (auth required)
	app.Get("/add_server", serverCertControllers.AddServerControll)                  // Получение списка серверов
	app.Post("/add_server", serverCertControllers.AddServerControll)                 // Добавление сервера
	app.Get("/server_list", serverCertControllers.ServerListController)              // Получение списка серверов
	app.Get("/add_server_entity", serverCertControllers.AddServerEntityController)   // Получение списка сущностей для серверных сертификатов
	app.Post("/add_server_entity", serverCertControllers.AddServerEntityController)  // Добавление сущности для серверных сертификатов
	app.Get("/entity_server_list", serverCertControllers.EntityServerListController) // Получение списка серверных сущностей
	app.Post("/remove_server", serverCertControllers.RemoveServer)
	app.Get("/add_certs", serverCertControllers.AddCertsControll)
	app.Post("/add_certs", serverCertControllers.AddCertsControll)
	app.Post("/remove_cert", serverCertControllers.RemoveCert)
	app.Post("/revoke_cert", serverCertControllers.RevokeCert) // отзыв сертификата
	app.Get("/cert_list", serverCertControllers.CertListController)
	app.Post("/cert_list", serverCertControllers.CertListController)
	app.Get("/revoke_certs", serverCertControllers.RevokeCertsController)        // Раздел - список сертификатов для отзыва
	app.Get("/cert_list_revoke", serverCertControllers.CertListRevokeController) // Список сертификатов для отзыва находится в RevokeCertsController
	app.Post("/revoke_certs", serverCertControllers.RevokeCertsController)
	app.Post("/rollback_cert", serverCertControllers.RollbackCert) // Откат сертификата
	app.Get("/take_cert", serverCertControllers.TakeCert)          // Скачать сертификат

	app.Get("/add_entity", usersCertControllers.AddEntityController)               // Получение сущности
	app.Post("/add_entity", usersCertControllers.AddEntityController)              // Добавление сущности
	app.Get("/entity_list", usersCertControllers.EntityListController)             // Получение списка сущностей
	app.Get("/add_oid", usersCertControllers.AddOIDController)                     // Получение списка OID
	app.Post("/add_oid", usersCertControllers.AddOIDController)                    // Добавление OID
	app.Get("/oid_list", usersCertControllers.OIDListController)                   // Получение списка OID
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
	app.Get("/add_entity_ca", caControllers.AddEntityExtCAController)     // Получение списка сущностей для внешних CA
	app.Post("/add_entity_ca", caControllers.AddEntityExtCAController)    // Добавление сущности для внешних CA
	app.Get("/entity_ca_list", caControllers.EntityCAListController)   // Получение списка сущностей для внешних CA
	app.Post("/remove_entity_ca", caControllers.RemoveEntityCA)        // Удаление сущности для внешних CA
	app.Get("/ext_ca", caControllers.AddExtCAController)               // Страница загрузки внешних CA сертификатов
	app.Post("/ext_ca", caControllers.AddExtCAController)              // Загрузка внешних CA сертификатов
	app.Get("/ext_ca_list", caControllers.ExtCAListController)         // Получение списка внешних CA сертификатов
	app.Post("/remove_ext_ca", caControllers.RemoveExtCA)              // Удаление внешнего CA сертификата

	app.Get("/add_ssh_key", sshControllers.AddSSHControll)         // Получение списка ssh ключей
	app.Post("/add_ssh_key", sshControllers.AddSSHControll)        // Добавление ssh ключа
	app.Get("/ssh_key_list", sshControllers.SSHCertListController) // Получение списка ssh ключей
	app.Post("/remove_ssh_key", sshControllers.RemoveSSHKey)       // Удаление ssh ключа

	app.Get("/cert_info", certInfoController.CertInfoController)  // Получение информации о сертификате
	app.Post("/cert_info", certInfoController.CertInfoController) // Загрузка сертификата для анализа

	// API keys management (UI, защищён session)
	app.Get("/api_keys", apiKeyControllers.APIKeyController)
	app.Post("/api_keys", apiKeyControllers.APIKeyController)
	app.Get("/api_keys_list", apiKeyControllers.APIKeyListController)
	app.Post("/remove_api_key", apiKeyControllers.RemoveAPIKey)

	app.Get("/logout", loginControllers.LogoutController)
}
