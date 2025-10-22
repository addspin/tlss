package controllers

import (
	"os"

	"github.com/gofiber/fiber/v3"
)

// GetCRL обрабатывает запрос на получение CRL файла
func GetUserCRL(c fiber.Ctx) error {
	// Путь к CRL файлу
	crlPath := "./crlFile/revokedUser.crl"

	// Проверяем существование файла
	if _, err := os.Stat(crlPath); os.IsNotExist(err) {
		return c.Status(fiber.StatusNotFound).JSON(fiber.Map{
			"error": "CRL file not found",
		})
	}

	// Устанавливаем заголовок для скачивания файла с правильным именем
	c.Set("Content-Disposition", "attachment; filename=revokedUser.crl")

	// Отправляем файл
	return c.SendFile(crlPath)
}
