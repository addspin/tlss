# 10. Фоновые чекеры и монитор

Пакет [`check`](../../check/) - четыре файла, пять горутин. Все запускаются из
`main.go` перед стартом слушателей.

| Файл | Горутина | Что делает |
|---|---|---|
| `tcp.go` | `TCPPortAvailable` | Проверяет доступность серверов по TCP |
| `valid.go` | `CheckValidCerts` | Пересчитывает `days_left`, помечает истёкшее |
| `recreate.go` | `RecreateCerts` | Перевыпускает истёкшие с флагом `recreate` |
| `mon.go` | `Monitore` | Следит, что первые три живы |

## TCP-чекер

Раз в `checkServer.checkServerInterval` обходит записи `server` и пробует
подключиться к порту, обновляя `server.server_status` (`online` / `offline`).

Ключевая деталь - таймаут:

```go
dialTimeout := utils.SelectTime(viper.GetString("add_server.unit"),
                                viper.GetInt("add_server.waitingToConnect"))
net.DialTimeout("tcp", address, dialTimeout)
```

Без явного таймаута `net.Dial` ждёт системный лимит TCP - около 75 секунд на macOS
и до 128 на Linux. Один недоступный хост блокировал бы весь цикл проверки, из-за чего
статусы остальных серверов обновлялись бы с огромной задержкой, а монитор счёл бы
чекер зависшим.

## Чекер валидности

Раз в `certsValidation.certsValidationInterval` обрабатывает пять сущностей:

| Объект | Действие |
|---|---|
| `certs`, `user_certs`, `ca_certs`, `ca_certs_ext` | Пересчёт `days_left`; при истечении `cert_status: 0 → 1` |
| `api_keys` | При истечении `expires_at` → `key_status = 1` |
| `est_users` | При истечении `user_expire_time` → `user_status = 1`, `max_uses = 0` |

Обрабатываются только записи со статусом `0` или `1` - отозванные (`2`) не трогаются,
иначе отзыв мог бы «самоотмениться».

## Чекер пересоздания

Раз в `recreateCerts.recreateCertsInterval` выбирает записи, у которых
**одновременно** `cert_status = 1` и `recreate = 1`, и вызывает соответствующий
`Recreate*Certificate`. Флаг `recreate` задаётся при выпуске переключателем в форме.

Обрабатываются `certs`, `user_certs` и `ca_certs` - то есть автопродление работает и
для CA, если у него выставлен флаг.

## Монитор

`Monitore` отвечает на вопрос «работают ли чекеры». Механика простая: каждый чекер в
конце цикла обновляет свою метку времени в глобальной структуре `Monitors`, а монитор
периодически сравнивает её с текущим временем.

```go
if duration > checkerInterval + (checkerInterval / 2) {
    статус = false   // чекер не отвечает
}
```

Запас в 50% компенсирует задержки выполнения.

### Два разных интервала

Здесь легко ошибиться, потому что интервалов два и они из разных секций конфигурации:

| Что | Откуда берётся | Смысл |
|---|---|---|
| **Частота опроса монитора** | `monitor.*` | Как часто монитор просыпается |
| **Порог живости** | `checkServer.*`, `recreateCerts.*`, `certsValidation.*` | Сколько чекер может молчать до признания мёртвым |

Первый передаётся в `Monitore` из `main.go`, второй вычисляется внутри
`checkMonitorXXX` при каждой проверке. Порог обязан следовать за расписанием чекера:
если чекер работает раз в 30 секунд, признавать его мёртвым через 5 секунд молчания
неправильно.

Чтобы не путать, параметры `Monitore` названы `tcpPollInterval`,
`recreateCertsPollInterval`, `checkValidCertsPollInterval` - они относятся именно к
опросу.

### Отображение

Статусы `Monitors.CheckTCPStatus`, `RecreateCertStatus`, `CheckValidCertsStatus`
читает `overviewController` и показывает на главной странице. Доступ к структуре
защищён мьютексом `MutexMonitor`.

## Как проверить

```bash
# Логи монитора
grep "CheckMonitor" logs/tlss.log | tail -20

# Ожидаемо: "Checker is working" для каждого из трёх
```

Проверить реакцию на сбой можно, увеличив интервал чекера в конфиге так, чтобы он
превысил порог, и перезапустив приложение - монитор начнёт писать
`Checker is not working`.

```bash
# Актуальность days_left
sqlite3 db/database.db "
  SELECT common_name, cert_expire_time, days_left, cert_status
  FROM certs WHERE cert_status IN (0,1) ORDER BY days_left LIMIT 5;"

# Статусы серверов
sqlite3 db/database.db "SELECT hostname, server_status FROM server;"
```
