package controllers

import (
	"os"

	"github.com/addspin/tlss/crl"
	"github.com/gofiber/fiber/v3"
)

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

// GenerateRootCACRL принудительно генерирует CRL для серверных и клиентских сертификатов подписанных Root CA
func GenerateRootCACRL(c fiber.Ctx) error {
	err := crl.GenerateRootCACRL()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка генерации CRL для серверных и клиентских сертификатов подписанных Root CA: " + err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "CRL для серверных и клиентских сертификатов подписанных Root CA успешно сгенерирован",
	})
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

// GenerateSubCACRL принудительно генерирует CRL для серверных и клиентских сертификатов подписанных Sub CA
func GenerateSubCACRL(c fiber.Ctx) error {
	err := crl.GenerateSubCACRL()
	if err != nil {
		return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{
			"status":  "error",
			"message": "Ошибка генерации CRL для серверных и клиентских сертификатов подписанных Sub CA: " + err.Error(),
		})
	}

	return c.JSON(fiber.Map{
		"status":  "success",
		"message": "CRL для серверных и клиентских сертификатов подписанных Sub CA успешно сгенерирован",
	})
}
