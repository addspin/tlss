# 06. CRL - списки отзыва

Реализация - пакет [`crl`](../../crl/crl.go), публикация - контроллер
[`CRLController.go`](../../controllers/serverCertControllers/CRLController.go).
Стандарт: **RFC 5280** (профиль CRL, §5). Криптография - `crypto/x509.CreateRevocationList`.

## Два независимых CRL

По RFC 5280 CRL подписывается тем же CA, который выпустил перечисленные в нём
сертификаты. Поэтому списков два, и они не взаимозаменяемы:

| CRL | Подписан | Содержит | Эндпоинт |
|---|---|---|---|
| **Sub CA CRL** | Sub CA | отозванные конечные сертификаты | `/api/v1/crl/subca/pem`, `/der` |
| **Root CA CRL** | Root CA | отозванные сертификаты Sub CA | `/api/v1/crl/rootca/pem`, `/der` |
| **Bundle** | - | оба блока подряд | `/api/v1/crl/bundleca/pem`, `/der` |

Bundle - не стандарт, а удобство для ручного просмотра. **Использовать его в CDP
нельзя**: `openssl crl` и большинство клиентов читают только первый PEM-блок из файла,
поэтому второй список молча игнорируется. В CDP сертификатов подставляются адреса
конкретных CRL из `CAcrl.subCACrlURL` и `CAcrl.rootCACrlURL`.

## Что попадает в Sub CA CRL

Три источника, у всех одинаковое условие - отозван и подписан **нашим** Sub CA:

```sql
SELECT ... FROM certs      WHERE cert_status = 2 AND signing_ca_id = 0
SELECT ... FROM user_certs WHERE cert_status = 2 AND signing_ca_id = 0
SELECT ... FROM est_certs  WHERE cert_status = 2 AND signing_ca_id = 0
```

Фильтр `signing_ca_id = 0` принципиален. Без него в список попали бы сертификаты,
выпущенные внешними CA, и получился бы CRL, подписанный нашим Sub CA, но содержащий
чужие серийные номера. Клиент, проверяющий такой сертификат, скачал бы CRL по CDP,
увидел бы несовпадение издателя и отбросил список как неприменимый. Для внешних CA
проверка отзыва работает через OCSP - [07-ocsp.md](07-ocsp.md).

Root CA CRL строится из `ca_certs` по условию `type_ca = 'Sub' AND cert_status = 2`.

## Записи об отзыве

`createRevokedEntry` формирует `pkix.RevokedCertificate`:

- **Серийный номер** - из hex-строки базы в `big.Int`.
- **Время отзыва** - парсится из `data_revoke` (RFC 3339). Если не разобралось,
  подставляется текущее время и пишется предупреждение в лог.
- **Причина** - расширение `reasonCode` (OID 2.5.29.21), ASN.1 ENUMERATED.
  Значение `unspecified (0)` не добавляется - так рекомендует RFC 5280 §5.3.1.

Отображение текстовой причины в код - `crl.GetRevocationReason` (RFC 5280 §5.3.1):

| Текст в базе | Код |
|---|---|
| `unspecified` / пусто | 0 |
| `keyCompromise` | 1 |
| `cACompromise` | 2 |
| `affiliationChanged` | 3 |
| `superseded` | 4 |
| `cessationOfOperation` | 5 |
| `certificateHold` | 6 |
| `removeFromCRL` | 8 |
| `privilegeWithdrawn` | 9 |
| `aACompromise` | 10 |

Функция приводит вход к нижнему регистру, поэтому все `case` записаны строчными
буквами. Эта же функция используется в OCSP - коды причин в обоих механизмах общие.

## Номер CRL и окно валидности

Метаданные лежат в `sub_ca_crl_info` и `root_ca_crl_info`: версия, алгоритм подписи,
издатель, `last_update`, `next_update`, `crl_number`, URL. При каждой генерации
`crl_number` инкрементируется - RFC 5280 §5.2.3 требует монотонного роста, иначе
клиент может счесть новый список устаревшим и не обновить кэш.

`nextUpdate` вычисляется как `now + CAcrl.updateInterval`. Если ключ конфигурации
прочитается неверно, интервал станет нулевым и `nextUpdate` совпадёт с `thisUpdate` -
клиенты будут считать список просроченным сразу после выпуска. Скрипт
`tests/crl/test_crl.sh` специально проверяет этот случай.

## Когда CRL перегенерируется

| Событие | Где вызывается |
|---|---|
| Старт приложения | `StartCombinedCRLGeneration` |
| По расписанию | тикер `CAcrl.updateInterval` |
| Отзыв сертификата | `RevokeCert`, `RevokeUserCert`, `RevokeESTCert` |
| Откат отзыва | `RollbackCert`, `RollbackUserCert`, `RollbackESTCert` |
| Пересоздание Sub CA | `RevokeCACertWithData` |
| Вручную | `POST /api/v1/crl/bundleca/generate` (нужен API-ключ со scope `write`) |

Перегенерация после каждого отзыва означает, что клиенту не нужно ждать суточного
тика - новый список доступен сразу. Важная деталь реализации: `CombinedCRL(db)`
вызывается **после** `tx.Commit()`. Внутри генератор открывает собственные соединения
к SQLite, которые не видят незакоммиченную транзакцию, и без коммита в список попал
бы прежний статус сертификата.

## Хранение и выдача

`CombinedCRL` пишет три записи в таблицу `crl` (`Sub`, `Root`, `Bundle`) в формате PEM.
Эндпоинты `/pem` отдают содержимое как есть, `/der` декодируют PEM обратно в DER.
Заголовки: `application/x-pem-file` и `application/pkix-crl` соответственно.

## Как проверить

```bash
./tests/crl/test_crl.sh              # последний EST-сертификат
./tests/crl/test_crl.sh <SERIAL>     # конкретный
```

Скрипт проверяет CDP в сертификате, парсинг обоих CRL, совпадение AKI сертификата с
AKI подписанта CRL, наличие серийного номера в списке, окно валидности и полную
цепочку через `openssl verify -crl_check_all`.

Вручную:

```bash
curl -sS http://tlss.lv.local:8080/api/v1/crl/subca/pem -o subca.crl
openssl crl -in subca.crl -text -noout | head -20
```
