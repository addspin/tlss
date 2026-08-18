package ocspControllers

import (
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	ocspResponder "github.com/addspin/tlss/ocsp"
	"github.com/gofiber/fiber/v3"
	"github.com/jmoiron/sqlx"
	_ "github.com/mattn/go-sqlite3"
	"github.com/spf13/viper"
	xocsp "golang.org/x/crypto/ocsp"
)

// ocspPathPrefix - префикс пути, после которого в GET-запросе идёт base64 полезной нагрузки
const ocspPathPrefix = "/ocsp/"

// maxRequestSize ограничивает размер OCSPRequest.
// По RFC 5019 §5 запросы про один сертификат укладываются в ~255 байт;
// запас на несколько килобайт закрывает нестандартных клиентов и режет мусор.
const maxRequestSize = 8192

// OCSPResponder обрабатывает OCSP-запросы по RFC 6960 Appendix A.1.
//
//	POST /ocsp        - тело содержит DER-encoded OCSPRequest
//	GET  /ocsp/{b64}  - base64(DER) с URL-кодированием в пути
func OCSPResponder(c fiber.Ctx) error {
	var reqDER []byte

	switch c.Method() {
	case fiber.MethodPost:
		// RFC 6960 A.1.1: Content-Type application/ocsp-request, тело - сырой DER
		reqDER = c.Body()

	case fiber.MethodGet:
		// RFC 6960 A.1.1 / RFC 5019 §5:
		// GET {url}/{url-encoding of base-64 encoding of the DER encoding of the OCSPRequest}
		payload, err := extractGETPayload(c)
		if err != nil {
			slog.Warn("OCSP: cannot decode GET payload", "error", err)
			return sendResponse(c, ocspResponder.Result{DER: xocsp.MalformedRequestErrorResponse})
		}
		reqDER = payload

	default:
		return c.Status(fiber.StatusMethodNotAllowed).SendString("Method not allowed")
	}

	if len(reqDER) == 0 || len(reqDER) > maxRequestSize {
		slog.Warn("OCSP: request size out of range", "size", len(reqDER))
		return sendResponse(c, ocspResponder.Result{DER: xocsp.MalformedRequestErrorResponse})
	}

	database := viper.GetString("database.path")
	db, err := sqlx.Open("sqlite3", database)
	if err != nil {
		slog.Error("OCSP: database error", "error", err)
		return sendResponse(c, ocspResponder.Result{DER: xocsp.InternalErrorErrorResponse})
	}
	defer db.Close()

	return sendResponse(c, ocspResponder.BuildResponse(db, reqDER))
}

// extractGETPayload достаёт base64 из пути GET-запроса и декодирует его в DER.
// Берётся оригинальный (не нормализованный) путь, чтобы сохранить %XX-последовательности.
func extractGETPayload(c fiber.Ctx) ([]byte, error) {
	raw := string(c.RequestCtx().URI().PathOriginal())

	idx := strings.Index(raw, ocspPathPrefix)
	if idx < 0 {
		return nil, fmt.Errorf("path prefix %q not found in %q", ocspPathPrefix, raw)
	}
	encoded := raw[idx+len(ocspPathPrefix):]
	if encoded == "" {
		return nil, fmt.Errorf("empty payload")
	}

	// Клиент обязан URL-кодировать base64, т.к. алфавит содержит '+', '/' и '='
	unescaped, err := url.PathUnescape(encoded)
	if err != nil {
		// Некоторые клиенты не кодируют вовсе - пробуем строку как есть
		unescaped = encoded
	}

	der, err := base64.StdEncoding.DecodeString(unescaped)
	if err != nil {
		return nil, fmt.Errorf("base64 decode failed: %w", err)
	}
	return der, nil
}

// sendResponse отправляет OCSPResponse с заголовками кэширования по RFC 5019 §6.
// Error-ответы (unauthorized, malformed, internalError) не подписаны и не кэшируются.
func sendResponse(c fiber.Ctx, res ocspResponder.Result) error {
	c.Set("Content-Type", "application/ocsp-response")

	if !res.Cacheable {
		c.Set("Cache-Control", "no-cache, no-store, must-revalidate")
		return c.Send(res.DER)
	}

	maxAge := int(time.Until(res.NextUpdate).Seconds())
	if maxAge < 0 {
		maxAge = 0
	}
	c.Set("Cache-Control", fmt.Sprintf("max-age=%d, public, no-transform, must-revalidate", maxAge))
	c.Set("Last-Modified", res.ThisUpdate.UTC().Format(http.TimeFormat))
	c.Set("Expires", res.NextUpdate.UTC().Format(http.TimeFormat))

	// RFC 5019 §6: ETag - HEX-представление SHA-1 от структуры OCSPResponse.
	// Здесь SHA-1 используется как идентификатор кэша, не как криптографическая функция.
	sum := sha1.Sum(res.DER)
	c.Set("ETag", fmt.Sprintf("%q", fmt.Sprintf("%x", sum)))

	return c.Send(res.DER)
}
