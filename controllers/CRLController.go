package controllers

import (
	"os"

	"github.com/addspin/tlss/crl"
	"github.com/gofiber/fiber/v3"
)

// принудительно генерирует CRL для Root CA и Sub CA
func GenerateCombinedCACRL(c fiber.Ctx) error {
	err := crl.CombinedCRL()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка генерации CRL для серверных и клиентских сертификатов подписанных Root CA и Sub CA: " + err.Error(),
		})
	}
	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "CRL для серверных и клиентских сертификатов подписанных Root CA и Sub CA успешно сгенерирован",
	})
}

// GetBudleCRL обрабатывает запрос на получение бандла файла CRL
func GetBundleCACRL(c fiber.Ctx) error {
	crlPath := "./crlFile/bundleca.crl"

	// Проверяем существование файла
	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}

	// Устанавливаем заголовки для CRL файла
	c.Set("Content-Disposition", "attachment; filename=bundleca.crl")
	c.Set("Content-Type", "application/pkix-crl")

	return c.SendFile(crlPath)
}
func GetBundleCAPemCRL(c fiber.Ctx) error {
	crlPath := "./crlFile/bundleca.pem"

	// Проверяем существование файла
	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}

	// Устанавливаем заголовки для CRL файла
	c.Set("Content-Disposition", "attachment; filename=bundleca.pem")
	c.Set("Content-Type", "application/x-pem-file")

	return c.SendFile(crlPath)
}

// GetCRL обрабатывает запрос на получение CRL файла
func GetRootCACRL(c fiber.Ctx) error {
	// Используем только CRL файл для серверных и клиентских сертификатов подписанных Sub CA
	crlPath := "./crlFile/rootca.crl"

	// Проверяем существование файла
	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}

	// Устанавливаем заголовки для CRL файла
	c.Set("Content-Disposition", "attachment; filename=rootca.crl")
	c.Set("Content-Type", "application/pkix-crl")

	// Отправляем файл
	return c.SendFile(crlPath)
}

// GetCRL обрабатывает запрос на получение CRL файла
func GetRootCAPemCRL(c fiber.Ctx) error {
	// Используем только CRL файл для серверных и клиентских сертификатов подписанных Sub CA
	crlPath := "./crlFile/rootca.pem"

	// Проверяем существование файла
	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}

	// Устанавливаем заголовки для CRL файла
	c.Set("Content-Disposition", "attachment; filename=rootca.pem")
	c.Set("Content-Type", "application/x-pem-file")

	// Отправляем файл
	return c.SendFile(crlPath)
}

// GetSubCACRL обрабатывает запрос на получение CRL файла
func GetSubCACRL(c fiber.Ctx) error {
	// Используем только CRL файл для серверных и клиентских сертификатов подписанных Sub CA
	crlPath := "./crlFile/subca.crl"

	// Проверяем существование файла
	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}

	// Устанавливаем заголовки для CRL файла
	c.Set("Content-Disposition", "attachment; filename=subca.crl")
	c.Set("Content-Type", "application/pkix-crl")

	// Отправляем файл
	return c.SendFile(crlPath)
}

// GetCRL обрабатывает запрос на получение CRL файла
func GetSubCAPemCRL(c fiber.Ctx) error {
	// Используем только CRL файл для серверных и клиентских сертификатов подписанных Sub CA
	crlPath := "./crlFile/subca.pem"

	// Проверяем существование файла
	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}

	// Устанавливаем заголовки для CRL файла
	c.Set("Content-Disposition", "attachment; filename=subca.pem")
	c.Set("Content-Type", "application/x-pem-file")

	// Отправляем файл
	return c.SendFile(crlPath)
}
