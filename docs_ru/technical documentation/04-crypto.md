# 04. Криптография (пакет `crypts`)

Здесь сосредоточена вся работа с ключами и сертификатами. Вся криптография -
стандартная библиотека Go плюс `golang.org/x/crypto` для SSH, bcrypt и PBKDF2.

## Файлы пакета

| Файл | Назначение |
|---|---|
| `aes.go` | Шифрование приватных ключей и паролей (AES-256-GCM) |
| `pbkdf2.go` | Вывод ключа из пароля администратора |
| `rsaRootCA.go` | Генерация корневого CA |
| `rsaSubCA.go` | Генерация промежуточного CA |
| `rsaExtractCA.go` | Кэш активного Sub CA (`ExtractCA`) |
| `extCA.go` | Разбор загруженных внешних CA, сопоставление ключей, выбор подписанта |
| `rsa.go`, `ecdsa.go`, `ed25519.go` | Выпуск и перевыпуск серверных сертификатов |
| `rsaUser.go`, `ecdsaUser.go`, `ed25519User.go` | То же для клиентских |
| `rsaEST.go`, `ecdsaEST.go`, `ed25519EST.go` | То же для EST-сертификатов, выданных через UI |
| `estSign.go` | Подпись CSR, пришедшего по протоколу EST |
| `estClientCAPool.go` | Пул доверенных CA для проверки клиентских сертификатов в mTLS |
| `san.go` | Разбор строки SAN на DNS / IP / email |
| `rsaSSH.go` | Генерация SSH-ключей |
| `saveOnServer.go` | Доставка сертификатов на удалённый сервер по SSH |
| `apiKey.go` | Генерация API-ключей |

## Защита приватных ключей

### Двухуровневая схема

```
пароль администратора + соль
          │ PBKDF2-SHA256, 100 000 итераций, 32 байта
          ▼
      ключ шифрования ──── расшифровывает ───> secret_key.key_data
                                                      │
                                                      ▼
                                              мастер-ключ (32 байта)
                                                      │ AES-256-GCM
                                                      ▼
                          приватные ключи сертификатов, SSH-ключи,
                          пароли PKCS#12 - в колонках private_key / password
```

Параметры PBKDF2 заданы в `crypts/pbkdf2.go`: `Iterations = 100000`, `KeySize = 32`,
хэш SHA-256.

Мастер-ключ живёт в памяти процесса в `crypts.AesSecretKey.Key` и используется всеми
компонентами: выпуском сертификатов, CRL, OCSP, доставкой по SSH.

### AES-256-GCM

`crypts/aes.go` использует режим GCM - аутентифицированное шифрование: подмена
шифротекста в базе будет обнаружена при расшифровке, а не приведёт к выдаче
испорченного ключа.

### Следствия

- Файл базы без пароля администратора не даёт доступа ни к одному приватному ключу.
- Потеря пароля означает безвозвратную потерю всех ключей - резервной копии
  мастер-ключа нет by design.
- Все операции подписи требуют, чтобы процесс был запущен и разблокирован; после
  рестарта пароль нужен снова (или берётся из `login.authConfig`).

## Иерархия CA

```
Root CA  (self-signed, RSA)
   └── Sub CA  (RSA)
         ├── серверные сертификаты   (certs)
         ├── клиентские сертификаты  (user_certs)
         └── EST-сертификаты         (est_certs, signing_ca_id = 0)

Внешние CA (ca_certs_ext, сгруппированы по entity_ca)
   └── сертификаты с signing_ca_id = entity_ca.id
```

### Профили сертификатов

| Тип | KeyUsage | ExtKeyUsage | IsCA |
|---|---|---|---|
| Root CA | CertSign, CRLSign, DigitalSignature | - | да, `MaxPathLen: 1` |
| Sub CA | CertSign, CRLSign, DigitalSignature | ClientAuth, ServerAuth | да, `MaxPathLen: 0` |
| Серверный | DigitalSignature, KeyEncipherment | ServerAuth, ClientAuth | нет |
| Клиентский | DigitalSignature, KeyEncipherment | ClientAuth | нет |
| EST | DigitalSignature, KeyEncipherment | ClientAuth | нет |

Расширения точек отзыва:

| Тип | CDP (RFC 5280 §4.2.1.13) | AIA / OCSP (§4.2.2.1) |
|---|---|---|
| Root CA | нет (самоподписан, проверяется через trust store) | нет |
| Sub CA | `CAcrl.rootCACrlURL` | `CAocsp.url` |
| Конечные | `CAcrl.subCACrlURL` | `CAocsp.url` |

### Кэш `ExtractCA` и его сброс

`crypts.ExtractCA` хранит распарсенные сертификат и ключ активного Sub CA, чтобы не
расшифровывать их при каждом выпуске. Заполняется при старте и лениво - если поле `nil`.

Критичный момент: при пересоздании Sub CA кэш **обязан** сбрасываться, иначе все
последующие сертификаты будут подписаны старым, уже отозванным ключом, а их AKI не
совпадёт с новым CRL и OCSP-ответами. Сброс выполняется в конце `GenerateRSASubCA`:

```go
ExtractCA.SubCAcert = nil
ExtractCA.SubCAKey = nil
```

Симптом при отсутствии сброса: в UI даты обновились, но `openssl x509 -text`
показывает старого издателя, а `openssl verify` не находит цепочку.

## Внешние CA

Пользователь загружает произвольный набор PEM-файлов (сертификаты и ключи).
Разбор в `extCA.go` идёт в четыре шага:

1. **`ParsePEMFiles`** - разбирает все PEM-блоки, раскладывая на сертификаты и ключи.
2. **`MatchKeysToCerts`** - сопоставляет ключ с сертификатом сравнением **публичных
   ключей**, а не имён файлов. Ключ может отсутствовать - тогда CA пригоден только
   для построения цепочки, но не для подписи.
3. **`DetermineCAType`** - определяет Root или Sub:
   - самоподписанный (`Subject == Issuer` и `AKI == SKI`) → Root
   - `IsCA` и `Subject != Issuer` → Sub
4. **`BuildCAExtRecords`** - шифрует ключи и складывает записи в `ca_certs_ext`.

### Выбор подписанта

`ExtractExtCA(db, entityCAId)` выбирает, каким именно CA из группы подписывать:

```sql
SELECT * FROM ca_certs_ext
WHERE entity_ca_id = ? AND private_key != '' AND cert_status = 0
ORDER BY CASE type_ca WHEN 'Sub' THEN 1 WHEN 'Intermediate' THEN 2 WHEN 'Root' THEN 3 ELSE 4 END
```

Берётся первая запись - то есть самый нижний CA в иерархии, у которого есть ключ.
Это соответствует практике: Root подписывает только промежуточные, а конечные
сертификаты выпускает Sub CA.

Определение типа и выбор подписанта имеют слабые места при нестандартных иерархиях,
например при совпадении CommonName у Root и Sub CA или при нескольких активных CA
одного типа в одной группе.

## Алгоритмы и длины ключей

| Алгоритм | Допустимые значения | Ограничения |
|---|---|---|
| RSA | 2048, 4096, 8192 | Единственный вариант для Root и Sub CA |
| ECDSA | 256, 384, 521 (P-224 поддерживается кодом, но не UI) | |
| ED25519 | фиксированно 256 | Не может подписывать OCSP-ответы |

Про ED25519: `golang.org/x/crypto/ocsp` в `CreateResponse` поддерживает только RSA и
ECDSA. Собственные CA всегда RSA, поэтому проблемы нет; но внешний CA на ED25519 не
сможет отвечать по OCSP - запрос завершится `internalError`.

## SAN

`crypts/san.go` разбирает строку с разделителями-запятыми и раскладывает значения по
типам: IP-адреса определяются через `net.ParseIP`, адреса с `@` - как email,
остальное - DNS-имена. Common Name добавляется в DNS-имена автоматически, поскольку
современные клиенты игнорируют CN при проверке имени хоста (RFC 6125).

## Доставка по SSH

`saveOnServer.go` подключается через `golang.org/x/crypto/ssh` и копирует сертификат
с ключом в каталог `server.cert_config_path`. Ключ берётся из `ssh_key`
(расшифровывается мастер-ключом), таймаут подключения - из `add_server.waitingToConnect`.

## Как проверить

```bash
# Профиль выпущенного сертификата
sqlite3 db/database.db "SELECT public_key FROM certs ORDER BY id DESC LIMIT 1;" \
  | openssl x509 -noout -text | grep -A2 -E "Key Usage|Extended Key Usage|CRL Distribution|Authority Information"

# Совпадение AKI сертификата с SKI активного Sub CA
sqlite3 db/database.db "SELECT public_key FROM ca_certs WHERE type_ca='Sub' AND cert_status=0;" \
  | openssl x509 -noout -text | grep -A1 "Subject Key Identifier"

# Проверка цепочки
sqlite3 db/database.db "SELECT public_key FROM ca_certs WHERE type_ca='Root' AND cert_status=0;" > /tmp/root.pem
sqlite3 db/database.db "SELECT public_key FROM ca_certs WHERE type_ca='Sub'  AND cert_status=0;" > /tmp/sub.pem
cat /tmp/root.pem /tmp/sub.pem > /tmp/chain.pem
sqlite3 db/database.db "SELECT public_key FROM certs ORDER BY id DESC LIMIT 1;" > /tmp/cert.pem
openssl verify -CAfile /tmp/chain.pem /tmp/cert.pem
```
