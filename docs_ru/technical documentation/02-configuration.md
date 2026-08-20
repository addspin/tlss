# 02. Конфигурация

Читается через **viper** из `config.yaml`. Файл ищется в рабочем каталоге и рядом
с исполняемым файлом. Если его нет - создаётся из встроенного `configInit.yaml`,
поэтому **при добавлении нового ключа его нужно вносить в оба файла**: иначе на
чистой установке ключ окажется пустым.

Все ключи читаются напрямую по строковому пути (`viper.GetString("CAcrl.subCACrlURL")`),
структура конфигурации в Go не описана. Это значит, что **опечатка в имени ключа не
вызовет ошибку** - viper молча вернёт нулевое значение. Способ проверки приведён в
конце раздела.

## app - сетевые параметры

```yaml
app:
  port: 43000          # UI и REST API
  est_port: 43001      # EST (всегда TLS, mTLS)
  crl_port: 8080       # CRL и OCSP
  crl_protocol: http   # http | https
  hostname: tlss.lv.local
  protocol: https      # http | https - только для UI
  certFile: https/tlss.lv.local.pem
  keyFile: https/tlss.lv.local.key
```

`hostname` используется как адрес привязки всех трёх слушателей. `certFile`/`keyFile`
общие для UI и EST; если они не заданы, EST-сервер не поднимается (в лог уходит
предупреждение), а UI при `protocol: https` завершится с ошибкой.

## logging

```yaml
logging:
  level: info    # debug | info | warn | error
  format: text   # text | json
  output: stdout # stdout | file | both
  file: logs/tlss.log
```

Обрабатывается в `utils/logger.go`, настраивает глобальный `slog`.

## login - первичная инициализация

```yaml
login:
  authConfig: true   # true - брать логин/пароль отсюда, false - спросить в консоли
  username: admin
  password: ...
  salt: ...
```

Используется **только при первом запуске**, когда таблица `secret_key` пуста: из
пароля и соли выводится ключ (PBKDF2), которым шифруется сгенерированный мастер-ключ.
При последующих запусках эти значения нужны для расшифровки. В продакшене разумно
ставить `authConfig: false` - тогда пароль вводится вручную и не лежит в файле.

## database

```yaml
database:
  path: db/database.db
```

## root_ca_tlss / sub_ca_tlss

```yaml
root_ca_tlss:
  commonName: TLSS Root CA
sub_ca_tlss:
  commonName: TLSS Sub CA
```

Читается только `sub_ca_tlss.commonName` - при пересоздании Sub CA. Ключ
`root_ca_tlss.commonName` в коде не используется: CN корневого CA вводится в форме UI.

## CAcrl - точки распространения CRL

```yaml
CAcrl:
  subCACrlURL: http://tlss.lv.local:8080/api/v1/crl/subca/pem
  rootCACrlURL: http://tlss.lv.local:8080/api/v1/crl/rootca/pem
  unit: hours
  updateInterval: 24
```

По RFC 5280 каждый сертификат ссылается на CRL **своего издателя**, поэтому адреса
разные и не взаимозаменяемы:

| Ключ | Попадает в CDP | Кто подписывает этот CRL |
|---|---|---|
| `subCACrlURL` | конечные сертификаты (server, client, EST) | Sub CA |
| `rootCACrlURL` | сертификаты Sub CA | Root CA |

`unit` + `updateInterval` задают и период перегенерации, и окно `nextUpdate` внутри CRL.

## CAocsp - точка OCSP

```yaml
CAocsp:
  url: http://tlss.lv.local:8080/ocsp
  unit: hours
  responseValidity: 24   # nextUpdate в ответе
```

Здесь адрес **один на всю иерархию** - в отличие от CRL. Респондер определяет
издателя не по URL, а по `IssuerNameHash`/`IssuerKeyHash` из самого запроса
(RFC 6960 §4.1.1), поэтому один эндпоинт обслуживает и Core CA, и внешние CA.

## CApath / ca_tlss - где хранить CA

```yaml
CApath:
  db: true      # хранить CA в базе
  server: false # хранить CA в файлах
ca_tlss:
  path_cert: ./root_ca_tlss/root_ca_tlss.pem
  path_key: ./root_ca_tlss/root_ca_tlss.key
```

Основной режим - `db: true`. Пути из `ca_tlss` работают как резервный источник: если
Root CA не найден в базе, `GenerateRSASubCA` и генератор Root CA CRL попробуют
прочитать его из файлов.

## add_server - SSH

```yaml
add_server:
  unit: seconds
  waitingToConnect: 3
```

Таймаут TCP-подключения при проверке доступности сервера и при доставке сертификатов
по SSH. Значение важно: без него неотвечающий хост блокировал бы чекер на десятки
секунд (системный таймаут TCP).

## Чекеры

```yaml
checkServer:        { unit: seconds, checkServerInterval: 10 }   # опрос TCP-портов
certsValidation:    { unit: seconds, certsValidationInterval: 30 } # пересчёт days_left
recreateCerts:      { unit: seconds, recreateCertsInterval: 5 }   # перевыпуск истёкших
```

## monitor - надзор за чекерами

```yaml
monitor:
  unitTCP: seconds
  TCPInterval: 5
  unitRecreateCerts: seconds
  RecreateCertsInterval: 3
  unitCheckValidCerts: seconds
  CheckValidCertsInterval: 10
```

Это **частота опроса монитора**, а не интервалы самих чекеров. Порог «чекер не
отвечает» вычисляется внутри монитора из настроек соответствующего чекера как
`интервал × 1.5`. Разделение легко перепутать - подробности в [10-checkers.md](10-checkers.md).

## overview

```yaml
overview:
  checkClientExpireDaysLeft: 30
  checkServerExpireDaysLeft: 30
```

Пороги, начиная с которых сертификат подсвечивается на главной как истекающий.

## est / estCSRAttrs

```yaml
est:
  cert_ttl_enrollment: 365   # срок сертификата, выданного через simpleenroll
estCSRAttrs:
  rfc9908: true              # true - RFC 9908, false - RFC 7030
```

`cert_ttl_enrollment` применяется только к первичной выдаче по Basic Auth. При
`simplereenroll` срок берётся из поля `ttl` предыдущего сертификата.

`rfc9908` переключает формат ответа `/csrattrs` между исходной структурой RFC 7030 и
более новой из RFC 9908 - разные клиенты понимают разные варианты. См. [08-est.md](08-est.md).

## Проверка целостности конфигурации

Так как опечатка в ключе не приводит к ошибке, полезно периодически сверять, что все
читаемые кодом ключи присутствуют в конфиге:

```bash
# Ключи, которые читает код
grep -rhoE 'viper\.Get[A-Za-z]+\("[^"]+"\)' --include="*.go" . \
  | grep -oE '"[^"]+"' | tr -d '"' | sort -u > /tmp/code_keys.txt

# Ключи, которые есть в конфиге
awk '/^[a-zA-Z_][a-zA-Z0-9_]*:[[:space:]]*(#.*)?$/ { s=$1; sub(/:.*/,"",s); next }
     /^  [a-zA-Z_]/ { k=$1; sub(/:.*/,"",k); if (s!="") print s"."k }' \
  config.yaml | sort -u > /tmp/cfg_keys.txt

echo "Код читает, но в конфиге нет:"; comm -23 /tmp/code_keys.txt /tmp/cfg_keys.txt
echo "В конфиге есть, код не читает:"; comm -13 /tmp/code_keys.txt /tmp/cfg_keys.txt
```

Первый список должен быть пустым. Второй допускает единственную запись -
`root_ca_tlss.commonName`.

Та же проверка полезна для `configInit.yaml`: расхождение между ним и `config.yaml`
означает, что новая установка получит неполную конфигурацию.
