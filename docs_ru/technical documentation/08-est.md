# 08. EST - Enrollment over Secure Transport

Реализация протокола **RFC 7030**: автоматическая выдача и обновление сертификатов
для устройств. Контроллеры - [`estControllers`](../../controllers/estControllers/),
подпись CSR - [`crypts/estSign.go`](../../crypts/estSign.go), аутентификация -
`middleware/estBasicAuth.go` и `middleware/estCertAuth.go`.

## Отдельный порт и mTLS

EST-сервер поднимается на `app.est_port` (по умолчанию 43001) и **всегда** работает
по TLS - этого требует RFC 7030 §3.3. Конфигурация TLS:

```go
tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
tlsConfig.ClientCAs  = clientCAPool   // crypts.BuildESTClientCAPool
```

`VerifyClientCertIfGiven` означает: клиентский сертификат не обязателен, но если
предъявлен - цепочка проверяется против пула наших CA. Такой режим позволяет одному
слушателю обслуживать и `simpleenroll` (Basic Auth, сертификата ещё нет), и
`simplereenroll` (mTLS).

Причина отдельного порта: клиентский сертификат запрашивается на этапе TLS-рукопожатия,
когда сервер ещё не знает URL. Включить mTLS «только для одного маршрута» невозможно,
а включать его на порту UI нежелательно - браузеры начнут показывать диалог выбора
сертификата.

## Эндпоинты

| Метод и путь | Аутентификация | RFC |
|---|---|---|
| `GET /.well-known/est/cacerts` | нет | 7030 §4.1 |
| `GET /.well-known/est/csrattrs` | нет | 7030 §4.5 |
| `POST /.well-known/est/simpleenroll` | HTTP Basic | 7030 §4.2 |
| `POST /.well-known/est/simplereenroll` | mTLS | 7030 §4.2.2 |

### cacerts

Отдаёт цепочку CA в виде «вырожденного» PKCS#7 (только сертификаты, без подписи):
`pkcs7.NewSignedData([]byte{})` + `AddCertificate` для каждого активного CA.
Тело - base64, заголовки `application/pkcs7-mime; smime-type=certs-only` и
`Content-Transfer-Encoding: base64`.

### csrattrs

Подсказывает клиенту, какие атрибуты сервер ожидает в CSR. Поддерживаются два
формата, переключаются флагом `estCSRAttrs.rfc9908`:

| Значение | Структура |
|---|---|
| `false` - RFC 7030 §4.5.2 | `SEQUENCE { OID commonName, Attribute { id-ExtensionReq, SET { OID subjectAltName } } }` |
| `true` - RFC 9908 | вместо `id-ExtensionReq` используется `id-aa-extensionReqTemplate` с вложенной `Extensions SEQUENCE` |

Флаг нужен потому, что клиенты разных поколений понимают разные варианты. Реально
сервер использует из CSR только `Subject.CommonName` и SAN - остальные расширения
(KeyUsage, ExtKeyUsage, BasicConstraints) задаются сервером и из CSR игнорируются.

### simpleenroll

1. `ESTBasicAuth` проверяет логин и пароль по таблице `est_users` (bcrypt), а также
   что аккаунт активен и счётчик `max_uses` не исчерпан.
2. Тело запроса декодируется: пробуется base64, затем PEM, затем сырой DER.
3. `crypts.SignCSR` разбирает PKCS#10, **проверяет подпись CSR** и подписывает
   сертификат выбранным CA (`est_users.signing_ca_id`).
4. Сертификат сохраняется в `est_certs` - это нужно для последующего reenroll.
5. `max_uses` уменьшается на единицу; при достижении нуля пользователь переводится
   в статус `disabled`.
6. Ответ - PKCS#7 с одним сертификатом (`pkcs7.DegenerateCertificate`), base64.

Срок действия берётся из `est.cert_ttl_enrollment`. Стандартного способа передать
желаемый срок в PKCS#10 не существует, поэтому это решение сервера.

### simplereenroll

1. `ESTCertAuth` берёт клиентский сертификат из TLS-состояния
   (`c.RequestCtx().TLSConnectionState().PeerCertificates[0]`) - цепочка уже проверена
   на уровне TLS.
2. Серийный номер ищется в `est_certs`. Это отсекает сертификаты, выпущенные через UI
   в обход EST, даже если они подписаны тем же CA.
3. Проверяется, что сертификат не отозван и не истёк.
4. **Сверяются Subject и SAN** нового CSR с предъявленным сертификатом
   (RFC 7030 §4.2.2). Расхождение - `403`.
5. Новый CSR подписывается с теми же `signing_ca_id` и `ttl`, что у предъявленного
   сертификата.
6. Новая запись сохраняется, **старый сертификат отзывается** с причиной `superseded`.

### Проверка неизменности имени

`checkIdentityUnchanged` сравнивает:

| Поле | Способ сравнения |
|---|---|
| Subject | побайтово по DER (`RawSubject`) |
| DNS-имена, email, IP, URI | как множества - порядок значений не важен |

Без этой проверки владелец любого действующего EST-сертификата мог бы выпустить себе
сертификат на произвольное имя: аутентификация подтверждает лишь факт владения ключом,
а содержимое CSR до этого никак не ограничивалось.

Атрибут `ChangeSubjectName` (RFC 6402), которым клиент мог бы явно запросить смену
имени, не поддерживается - любое расхождение отклоняется.

EST-пользователь на этом шаге не нужен: по RFC достаточно валидного сертификата.
Поле `est_user_id` переносится в новую запись только как исторический след.

## EST-пользователи

Таблица `est_users` - учётные записи для первичной выдачи:

| Поле | Смысл |
|---|---|
| `password_hash` | bcrypt |
| `max_uses` | сколько сертификатов ещё можно выпустить |
| `ttl`, `user_expire_time` | срок жизни **аккаунта**, не сертификата |
| `user_status` | `0` активен, `1` истёк, `3` отключён (исчерпан `max_uses`) |
| `signing_ca_id` | каким CA подписывать выданные этому пользователю сертификаты |

Два независимых механизма блокировки:

- `max_uses` доходит до нуля → `user_status = 3` (выставляется в `SimpleEnroll`)
- истекает `user_expire_time` → `user_status = 1` (выставляет чекер `CheckValidCerts`)

В обоих случаях `ESTBasicAuth` вернёт 401.

Косвенное следствие: выбор CA для устройства делается через выбор учётной записи -
клиент указывает лишь логин и пароль, а какой CA подпишет, определяет запись в `est_users`.

## UI

Три раздела в меню:

| Раздел | Маршрут | Назначение |
|---|---|---|
| Add EST users | `/est_users` | Создание и удаление учётных записей |
| Add EST certs | `/add_est_certs` | Выпуск сертификата вручную, без протокола |
| Revoke EST certs | `/revoke_est_certs` | Отзыв, откат, удаление |

Ручной выпуск через UI кладёт запись в ту же `est_certs`, поэтому такой сертификат
можно потом обновлять по `simplereenroll`.

## Как проверить

```bash
./tests/est/test_est.sh <username> <password>
```

Скрипт проходит полный цикл: `cacerts` → генерация CSR → `simpleenroll` → проверка
цепочки → `simplereenroll` по mTLS → сверка статусов в базе → проверка блокировки
по `max_uses`.

Вручную:

```bash
# Цепочка CA
curl -sk https://tlss.lv.local:43001/.well-known/est/cacerts \
  | base64 -d | openssl pkcs7 -inform DER -print_certs -noout -text

# Атрибуты CSR
curl -sk https://tlss.lv.local:43001/.well-known/est/csrattrs \
  | base64 -d | openssl asn1parse -inform DER

# Выпуск
openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=device-01"
openssl req -in client.csr -outform DER | base64 | \
  curl -sk -u "user:pass" -X POST -H "Content-Type: application/pkcs10" \
    --data-binary @- https://tlss.lv.local:43001/.well-known/est/simpleenroll \
  | base64 -d | openssl pkcs7 -inform DER -print_certs -out client.crt

# Обновление по mTLS
openssl req -new -newkey rsa:2048 -nodes -keyout client2.key -out client2.csr -subj "/CN=device-01"
openssl req -in client2.csr -outform DER | base64 | \
  curl -sk --cert client.crt --key client.key -X POST -H "Content-Type: application/pkcs10" \
    --data-binary @- https://tlss.lv.local:43001/.well-known/est/simplereenroll
```
