# 09. REST API и аутентификация

API живёт на основном порту (`app.port`) под префиксом `/api/v1/`. Обработчики -
те же контроллеры, что обслуживают UI, но с отдельными «API»-функциями,
возвращающими JSON.

## Модель аутентификации

В приложении три независимых механизма, каждый в своём middleware:

| Механизм | Middleware | Где применяется |
|---|---|---|
| Сессии | `AuthMiddleware` | Веб-интерфейс |
| API-ключ | `APIKeyAuth(scope)` | `/api/v1/*` |
| Basic / mTLS | `ESTBasicAuth`, `ESTCertAuth` | EST-эндпоинты (другой порт) |

`AuthMiddleware` навешивается на всё основное приложение, но пропускает без
session-проверки два префикса - `/api/v1/` и `/.well-known/est/`, поскольку они
защищены своими middleware на уровне маршрутов. Также он пропускает публичные пути:

```
/           /login      /overview      /cert_info
/api/v1/crl/{subca,rootca,bundleca}/{pem,der}
```

и статику по расширениям (`.css`, `.js`, `.svg`, `.ico`, шрифты).

Отдельно существует **внутренний API-ключ** - случайное значение, генерируемое при
старте (`crypts.GetInternalAPIKey`). Он живёт только в памяти и используется
фоновыми задачами для обращения к собственным эндпоинтам.

## API-ключи

### Как устроено хранение

В базе лежит не сам ключ, а `HMAC-SHA256(мастер-ключ, ключ)` в hex. Восстановить
исходное значение из базы нельзя - оно показывается ровно один раз при создании.

```go
h := hmac.New(sha256.New, secret)   // secret = crypts.AesSecretKey.Key
```

HMAC, а не обычный хэш, выбран потому, что защищённость завязана на мастер-ключ: даже
получив копию базы, злоумышленник не сможет подобрать ключ офлайн.

### Проверка запроса

`APIKeyAuth(requiredScope)` выполняет:

1. Извлечение ключа - заголовок `X-API-Key` либо `Authorization: Bearer <key>`.
2. Вычисление HMAC и поиск строки в `api_keys` по `key_hash` (единственный запрос
   к базе, без промежуточного кэша в памяти).
3. Проверку `key_status` (`0` - активен, `1` - истёк) и срока `expires_at`.
4. Проверку scope: строка `scopes` хранится через запятую, требуемое значение должно
   в ней присутствовать. Пустой `scopes` трактуется как отсутствие прав.
5. Обновление `last_used` и IP клиента.

Ошибки: `401` - ключ не найден, истёк или отключён; `403` - недостаточный scope.

### Scope

| Scope | Права |
|---|---|
| `read` | Получение списков |
| `write` | Создание сертификатов, серверов, сущностей, генерация CRL |

## Эндпоинты

### Публичные - без аутентификации

| Метод | Путь | Ответ |
|---|---|---|
| GET | `/api/v1/crl/subca/pem` \| `/der` | Sub CA CRL |
| GET | `/api/v1/crl/rootca/pem` \| `/der` | Root CA CRL |
| GET | `/api/v1/crl/bundleca/pem` \| `/der` | Оба CRL подряд |

Дублируются на публичном порту (`app.crl_port`) - именно туда указывают CDP
сертификатов. На основном порту оставлены для совместимости.

### Требуют API-ключ

| Метод | Путь | Scope | Назначение |
|---|---|---|---|
| POST | `/api/v1/crl/bundleca/generate` | `write` | Принудительная перегенерация CRL |
| POST | `/api/v1/server/add_server` | `write` | Добавить сервер |
| POST | `/api/v1/server/add_entity` | `write` | Добавить серверную сущность |
| POST | `/api/v1/server/add_certs` | `write` | Выпустить серверный сертификат |
| GET | `/api/v1/server/entity_server_list` | `read` | Список серверных сущностей |
| GET | `/api/v1/server/ssh_key_list` | `read` | Список SSH-ключей |
| GET | `/api/v1/users/entity_list` | `read` | Список клиентских сущностей |
| GET | `/api/v1/users/oid_list` | `read` | Список OID |
| POST | `/api/v1/users/add_certs` | `write` | Выпустить клиентский сертификат |

## Примеры

```bash
KEY="<ключ, показанный при создании>"

# Список сущностей
curl -sk -H "X-API-Key: $KEY" \
  https://tlss.lv.local:43000/api/v1/users/entity_list

# То же через Bearer
curl -sk -H "Authorization: Bearer $KEY" \
  https://tlss.lv.local:43000/api/v1/server/entity_server_list

# Выпуск клиентского сертификата
curl -sk -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{
    "EntityId": 1,
    "Algorithm": "RSA",
    "KeyLength": 4096,
    "TTL": 365,
    "CommonName": "user@example.com",
    "CountryName": "RU",
    "StateProvince": "Udmurt Republic",
    "LocalityName": "Izhevsk",
    "Organization": "LV Inc.",
    "OrganizationUnit": "IT",
    "Email": "user@example.com",
    "Password": "container-password"
  }' \
  https://tlss.lv.local:43000/api/v1/users/add_certs

# Перегенерация CRL
curl -sk -X POST -H "X-API-Key: $KEY" \
  https://tlss.lv.local:43000/api/v1/crl/bundleca/generate
```

## Управление ключами

Раздел **API → API keys** в UI. При создании задаются имя, scope и TTL; значение
ключа показывается один раз. Просроченные ключи помечаются чекером `CheckValidCerts`
(`key_status = 1`) и перестают работать.
