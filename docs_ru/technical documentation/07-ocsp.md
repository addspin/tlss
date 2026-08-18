# 07. OCSP - проверка статуса онлайн

Реализация - пакет [`ocsp`](../../ocsp/ocspResponder.go), HTTP-слой -
[`OCSPController.go`](../../controllers/ocspControllers/OCSPController.go).
Библиотека - `golang.org/x/crypto/ocsp`.

## Стандарты

| RFC | Что взято |
|---|---|
| **RFC 6960** | Формат запроса и ответа, подбор издателя по хэшам, статусы, `responderID` |
| **RFC 5019** | Облегчённый профиль: обязательный `nextUpdate`, `unauthorized` на неизвестный serial, HTTP-кэширование |
| **RFC 5280** | Расширение AIA (`id-ad-ocsp`), коды причин отзыва |

## Принятые решения

| Вопрос | Выбор | Обоснование |
|---|---|---|
| Чем подписывать | ключом самого CA (`responderID = byName`) | Ключи CA и так используются онлайн для выпуска сертификатов и CRL; делегированный responder-сертификат добавил бы сущностей без выигрыша в безопасности |
| Nonce (RFC 8954) | не поддерживается | Профиль RFC 5019: ответы кэшируемы. Клиентам нужен флаг `-no_nonce` |
| Неизвестный serial | `unauthorized (6)` | RFC 5019 §2.2.3 - не даёт использовать респондер как оракул для перебора серийных номеров |

## Эндпоинты

Живут на публичном HTTP-слушателе (`app.crl_port`, по умолчанию 8080) - там же,
где CRL:

```
POST /ocsp           тело - DER-encoded OCSPRequest
GET  /ocsp/{base64}  base64(DER) с URL-кодированием в пути
```

Оба варианта описаны в RFC 6960 Appendix A.1. GET нужен для кэширования на прокси;
RFC 5019 §5 предписывает клиентам использовать его для запросов короче 255 байт.

Разбор GET требует аккуратности: алфавит base64 содержит `+`, `/` и `=`, которые
клиент обязан закодировать как `%2B`, `%2F`, `%3D`. Контроллер берёт **оригинальный**
путь (`c.RequestCtx().URI().PathOriginal()`), чтобы не потерять `%XX`, и лишь затем
раскодирует. Если клиент не закодировал - предпринимается попытка разобрать строку как есть.

## Как работает подбор издателя

Запрос не содержит имени CA - только хэши (RFC 6960 §4.1.1):

- `IssuerNameHash` - хэш DER-представления Subject издателя
- `IssuerKeyHash` - хэш содержимого BIT STRING `subjectPublicKey` (без тега и unused bits)

Алгоритм хэширования выбирает клиент (обычно SHA-1). Респондер:

1. `loadCACandidates` собирает всех возможных подписантов: Core Sub CA, Core Root CA
   и каждый активный внешний CA с приватным ключом.
2. `matchIssuer` вычисляет для каждого кандидата оба хэша **тем же алгоритмом**, что
   в запросе, и ищет совпадение.
3. Найденный CA определяет область поиска серийного номера.

Именно поэтому в AIA всех сертификатов стоит **один** URL - в отличие от CRL, где
адреса разные. Один эндпоинт обслуживает всю иерархию.

## Области ответственности

| `scopeKind` | Кто подписывает | Где ищется serial |
|---|---|---|
| `scopeCoreEndEntity` | Core Sub CA | `certs`, `user_certs`, `est_certs` с `signing_ca_id = 0` |
| `scopeCoreSubCA` | Core Root CA | `ca_certs` с `type_ca = 'Sub'` |
| `scopeExternal` | внешний CA | те же три таблицы с `signing_ca_id = entity_ca.id` |

Серийный номер приводится к формату базы: `strings.ToUpper(req.SerialNumber.Text(16))`.

## Формирование ответа

```go
template := xocsp.Response{
    SerialNumber: req.SerialNumber,
    ThisUpdate:   now,
    NextUpdate:   now.Add(validity),  // RFC 5019 §2.2.4 - обязателен
    IssuerHash:   req.HashAlgorithm,  // обязан совпадать с запросом
}
```

Соответствие статусов:

| `cert_status` в базе | Статус OCSP | Пояснение |
|---|---|---|
| `0` valid | `good` | |
| `1` expired | `good` | RFC 6960 §2.2: OCSP сообщает **только об отзыве**. Срок действия клиент проверяет сам по `NotAfter` |
| `2` revoked | `revoked` + время и причина | Причина - через `crl.GetRevocationReason`, общую с CRL |

Ошибочные ситуации возвращаются как валидные неподписанные `OCSPResponse` с
соответствующим `responseStatus`, а не как HTTP-ошибки:

| Ситуация | Ответ |
|---|---|
| Не разобрался запрос | `malformedRequest (1)` |
| Нет доступных CA / ошибка подписи | `internalError (2)` |
| Неизвестный издатель или serial | `unauthorized (6)` |

## Кэширование (RFC 5019 §6)

Для подписанных ответов проставляются:

```
Cache-Control: max-age=<до nextUpdate>, public, no-transform, must-revalidate
Last-Modified: <thisUpdate>
Expires: <nextUpdate>
ETag: "<SHA-1 hex от тела ответа>"
```

SHA-1 здесь - не криптографическая функция, а идентификатор кэша; такой формат прямо
задан в RFC 5019. Ответы с ошибками помечаются `no-cache, no-store` - кэшировать
`unauthorized` нельзя.

## Как проверить

```bash
./tests/ocsp/test_ocsp.sh                 # последний серверный сертификат
./tests/ocsp/test_ocsp.sh <SERIAL>        # конкретный
./tests/revocation/test_revocation.sh     # сверка БД ↔ CRL ↔ OCSP
```

Вручную:

```bash
sqlite3 db/database.db "SELECT public_key FROM ca_certs WHERE type_ca='Sub' AND cert_status=0;" > sub_ca.pem
sqlite3 db/database.db "SELECT public_key FROM certs ORDER BY id DESC LIMIT 1;" > cert.pem

openssl ocsp -issuer sub_ca.pem -cert cert.pem \
  -url http://tlss.lv.local:8080/ocsp -no_nonce -CAfile sub_ca.pem -resp_text
```

Ожидаемый вывод содержит `Cert Status: good` (или `revoked`) и `Response verify OK`.
