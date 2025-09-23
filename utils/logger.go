package utils

import (
	"fmt"
	"io"
	"log"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

// SetupSlogLogger настраивает структурированное логирование с slog
func SetupSlogLogger() (*os.File, error) {
	// Получаем настройки логирования из конфига
	level := strings.ToLower(viper.GetString("logging.level"))
	format := strings.ToLower(viper.GetString("logging.format"))
	output := strings.ToLower(viper.GetString("logging.output"))
	logFile := viper.GetString("logging.file")

	// Устанавливаем значения по умолчанию
	if level == "" {
		level = "info"
	}
	if format == "" {
		format = "json"
	}
	if output == "" {
		output = "file"
	}
	if logFile == "" {
		logFile = "/var/log/tlss.log"
	}

	// Определяем уровень логирования
	var logLevel slog.Level
	switch level {
	case "debug":
		logLevel = slog.LevelDebug
	case "info":
		logLevel = slog.LevelInfo
	case "warn", "warning":
		logLevel = slog.LevelWarn
	case "error":
		logLevel = slog.LevelError
	default:
		logLevel = slog.LevelInfo
	}

	// Настраиваем вывод
	var writer io.Writer
	var file *os.File
	var err error

	switch output {
	case "stdout":
		writer = os.Stdout
	case "file":
		// Создаем директорию для лог файла
		logDir := filepath.Dir(logFile)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			// Если не можем создать в /var/log, используем локальную директорию
			logFile = "./logs/tlss.log"
			logDir = filepath.Dir(logFile)
			if err := os.MkdirAll(logDir, 0755); err != nil {
				return nil, fmt.Errorf("не удалось создать директорию для логов: %v", err)
			}
		}

		file, err = os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("не удалось открыть лог файл %s: %v", logFile, err)
		}
		writer = file
	case "both":
		// Создаем директорию для лог файла
		logDir := filepath.Dir(logFile)
		if err := os.MkdirAll(logDir, 0755); err != nil {
			logFile = "./logs/tlss.log"
			logDir = filepath.Dir(logFile)
			if err := os.MkdirAll(logDir, 0755); err != nil {
				return nil, fmt.Errorf("не удалось создать директорию для логов: %v", err)
			}
		}

		file, err = os.OpenFile(logFile, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("не удалось открыть лог файл %s: %v", logFile, err)
		}
		writer = io.MultiWriter(os.Stdout, file)
	default:
		writer = os.Stdout
	}

	// Создаем обработчик логов
	var handler slog.Handler
	handlerOpts := &slog.HandlerOptions{
		Level:     logLevel,
		AddSource: true, // Добавляем информацию о файле и строке
	}

	if format == "json" {
		handler = slog.NewJSONHandler(writer, handlerOpts)
	} else {
		handler = slog.NewTextHandler(writer, handlerOpts)
	}

	// Устанавливаем глобальный логгер
	logger := slog.New(handler)
	slog.SetDefault(logger)

	// Также настраиваем стандартный log для совместимости
	if output != "stdout" {
		log.SetOutput(writer)
	}
	log.SetFlags(0) // Убираем стандартные флаги, так как slog управляет форматированием

	slog.Info("Логирование настроено",
		"level", level,
		"format", format,
		"output", output,
		"file", logFile)

	return file, nil
}
