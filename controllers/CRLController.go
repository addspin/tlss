package controllers

import (
	"os"

	"github.com/gofiber/fiber/v3"
)

// GetCRL обрабатывает запрос на получение CRL файла
func GetCRL(c fiber.Ctx) error {
	// Путь к CRL файлу
	crlPath := "./crlFile/revoked.crl"

	// Проверяем существование файла
	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL файл не найден",
		})
	}

	// Устанавливаем заголовок для скачивания файла с правильным именем
	c.Set("Content-Disposition", "attachment; filename=revoked.crl")

	// Отправляем файл
	return c.SendFile(crlPath)
}
