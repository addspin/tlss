# 03. База данных

Одна база SQLite, путь - `database.path`. Схемы описаны в пакете `models` как
константы `Schema*` и выполняются при каждом старте через `CREATE TABLE IF NOT EXISTS`.
Работа с БД - через `sqlx`, маппинг по тегам `db:"..."`.

## Таблицы

| Таблица | Назначение | Модель |
|---|---|---|
| `secret_key` | Мастер-ключ AES, зашифрованный паролем администратора | `models.SchemaKey` |
| `users` | Учётные записи UI | `models.UsersData` |
| `server` | Удалённые серверы для доставки сертификатов по SSH | `models.SchemaServer` |
| `ssh_key` | SSH-ключи для подключения к серверам | `models.SchemaSSHKey` |
| `ca_certs` | Собственные Root и Sub CA | `models.SchemaCA` |
| `ca_certs_ext` | Загруженные внешние CA | `models.SchemaCAExt` |
| `entity_ca` | Группы внешних CA | `models.SchemaEntityCA` |
| `certs` | Серверные сертификаты | `models.SchemaCerts` |
| `entity` | Сущности для клиентских сертификатов | `models.SchemaEntity` |
| `oid` | Пользовательские OID | `models.SchemaOID` |
| `user_certs` | Клиентские сертификаты | `models.SchemaUserCerts` |
| `est_users` | Учётные записи для EST Basic Auth | `models.SchemaESTUser` |
| `est_certs` | Сертификаты, выданные через EST или UI EST | `models.SchemaESTCerts` |
| `crl` | Готовые CRL (Sub, Root, Bundle) | `models.SchemaCRL` |
| `sub_ca_crl_info`, `root_ca_crl_info` | Счётчики и метаданные CRL | `models.SchemaCrlInfo*` |
| `api_keys` | Ключи доступа к REST API | `models.SchemaAPIKey` |

## Общие соглашения

Три таблицы сертификатов (`certs`, `user_certs`, `est_certs`) и `ca_certs` намеренно
используют одинаковые имена колонок - это позволяет чекерам, CRL и OCSP работать с
ними единообразно.

| Колонка | Смысл |
|---|---|
| `serial_number` | Серийный номер в **верхнем регистре hex, без ведущих нулей** |
| `public_key` | Сертификат в PEM |
| `private_key` | Приватный ключ в PEM, зашифрованный AES-256-GCM |
| `cert_create_time`, `cert_expire_time` | Время в RFC 3339 с локальным смещением |
| `days_left` | Дней до истечения, пересчитывается чекером |
| `cert_status` | `0` - valid, `1` - expired, `2` - revoked |
| `data_revoke` | Время отзыва (RFC 3339) или пустая строка |
| `reason_revoke` | Причина отзыва: `keyCompromise`, `superseded`, `unspecified`… |
| `signing_ca_id` | `0` - подписано собственным Sub CA, `>0` - `entity_ca.id` внешнего CA |

### Формат серийного номера

Везде применяется `strings.ToUpper(serialNumber.Text(16))`. Ведущие нули не
добавляются, поэтому длина строки может быть нечётной. При сравнении с выводом
`openssl` это важно: openssl дополняет номер до чётного числа цифр, и `3CEF…`
в базе отображается как `03CEF…` в CRL. Скрипты проверки учитывают оба варианта.

### Формат времени

Все временные метки пишутся как `time.Now().Format(time.RFC3339)` - со **смещением
локальной зоны**, например `2026-08-14T09:45:12+04:00`. В CRL и OCSP то же самое
время выводится в UTC (`Aug 14 05:45:12 2026 GMT`), потому что RFC 5280 §5.1.2.6
требует Zulu. Это не рассинхрон, а разные представления одного момента.

### Смысл `signing_ca_id`

Ключевое поле для разделения зон ответственности:

| Значение | Кто подписал | CRL | OCSP |
|---|---|---|---|
| `0` | собственный Sub CA | попадает в Sub CA CRL | отвечает Sub CA |
| `>0` | внешний CA с этим `entity_ca.id` | **не попадает** | отвечает внешний CA |

Сертификаты внешних CA исключены из CRL намеренно: наш CRL подписан собственным
Sub CA и для чужой иерархии неприменим - клиент отбросит его при проверке. Через
OCSP они обслуживаются корректно, так как ответ подписывается ключом того же
внешнего CA. Подробности - [06-crl.md](06-crl.md) и [07-ocsp.md](07-ocsp.md).

## Связи

```
entity_ca ──1:N──> ca_certs_ext        группа внешних CA и её сертификаты
    │
    └──── signing_ca_id ────> certs / user_certs / est_certs

entity ────1:N────> user_certs         сущность и её клиентские сертификаты
server ────1:N────> certs              сервер и его сертификаты
ssh_key ───N:1────  server             ключ, которым ходим на сервер
est_users ─1:N────> est_certs          EST-пользователь и выданные ему сертификаты
```

Внешних ключей на уровне SQLite почти нет (кроме `est_certs.est_user_id`),
целостность поддерживается кодом.

## Миграции

Выполняются в `main.go` сразу после создания таблиц. Приём простой: `ALTER TABLE
ADD COLUMN` без проверки, ошибка «duplicate column» игнорируется - это делает
операцию идемпотентной.

```go
db.Exec("ALTER TABLE api_keys ADD COLUMN key_status INTEGER DEFAULT 0")
db.Exec("ALTER TABLE certs ADD COLUMN signing_ca_id INTEGER DEFAULT 0")
db.Exec("ALTER TABLE user_certs ADD COLUMN signing_ca_id INTEGER DEFAULT 0")
db.Exec("ALTER TABLE ssh_key ADD COLUMN passphrase TEXT NOT NULL DEFAULT ''")
```
**Важно:** новые колонки нужно добавлять и в константу `Schema*` в `models`, и в
миграцию. Схема нужна для чистой установки, миграция - для существующих баз.
Если добавить только в схему, старые базы не получат колонку и запросы упадут.

## Полезные запросы

```bash
# Состояние сертификатов по статусам
sqlite3 db/database.db "
  SELECT 'certs' t, cert_status, COUNT(*) FROM certs GROUP BY cert_status
  UNION ALL SELECT 'user_certs', cert_status, COUNT(*) FROM user_certs GROUP BY cert_status
  UNION ALL SELECT 'est_certs', cert_status, COUNT(*) FROM est_certs GROUP BY cert_status;"

# Что подписано внешними CA
sqlite3 db/database.db "SELECT signing_ca_id, COUNT(*) FROM certs GROUP BY signing_ca_id;"

# Активные CA
sqlite3 db/database.db "SELECT id, type_ca, common_name, cert_status FROM ca_certs ORDER BY id;"

# Найти сертификат по серийному номеру во всех таблицах
S=3CEF5CDBA445C409C36D22718667676
sqlite3 db/database.db "
  SELECT 'certs', common_name, cert_status FROM certs WHERE serial_number='$S'
  UNION ALL SELECT 'user_certs', common_name, cert_status FROM user_certs WHERE serial_number='$S'
  UNION ALL SELECT 'est_certs', common_name, cert_status FROM est_certs WHERE serial_number='$S';"
```
