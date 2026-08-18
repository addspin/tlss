# 10. Background checkers and the monitor

The [`check`](../../check/) package - four files, five goroutines. All of them are
started from `main.go` before the listeners come up.

| File | Goroutine | What it does |
|---|---|---|
| `tcp.go` | `TCPPortAvailable` | Checks server reachability over TCP |
| `valid.go` | `CheckValidCerts` | Recalculates `days_left`, marks expired entries |
| `recreate.go` | `RecreateCerts` | Reissues expired certificates flagged with `recreate` |
| `mon.go` | `Monitore` | Watches that the first three are alive |

## TCP checker

Every `checkServer.checkServerInterval` it walks the `server` records and tries to
connect to the port, updating `server.server_status` (`online` / `offline`).

The key detail is the timeout:

```go
dialTimeout := utils.SelectTime(viper.GetString("add_server.unit"),
                                viper.GetInt("add_server.waitingToConnect"))
net.DialTimeout("tcp", address, dialTimeout)
```

Without an explicit timeout `net.Dial` waits for the system TCP limit - roughly 75
seconds on macOS and up to 128 on Linux. A single unreachable host would block the whole
check cycle, so the status of every other server would be updated with a huge delay and
the monitor would consider the checker stuck.

## Validity checker

Every `certsValidation.certsValidationInterval` it processes five kinds of records:

| Object | Action |
|---|---|
| `certs`, `user_certs`, `ca_certs`, `ca_certs_ext` | Recalculates `days_left`; on expiry `cert_status: 0 -> 1` |
| `api_keys` | On `expires_at` passing -> `key_status = 1` |
| `est_users` | On `user_expire_time` passing -> `user_status = 1`, `max_uses = 0` |

Only records with status `0` or `1` are processed - revoked ones (`2`) are left alone,
otherwise a revocation could effectively undo itself.

## Reissuance checker

Every `recreateCerts.recreateCertsInterval` it selects records that have **both**
`cert_status = 1` and `recreate = 1` and calls the matching `Recreate*Certificate`. The
`recreate` flag is set by a switch in the issuance form.

It processes `certs`, `user_certs` and `ca_certs` - so auto-renewal works for CAs too if
the flag is set on them.

## The monitor

`Monitore` answers the question "are the checkers running". The mechanics are simple:
each checker updates its timestamp in the global `Monitors` struct at the end of a cycle,
and the monitor periodically compares it against the current time.

```go
if duration > checkerInterval + (checkerInterval / 2) {
    status = false   // the checker is not responding
}
```

The 50% margin absorbs execution delays.

### Two different intervals

This is easy to get wrong, because there are two intervals and they come from different
configuration sections:

| What | Where it comes from | Meaning |
|---|---|---|
| **Monitor polling frequency** | `monitor.*` | How often the monitor wakes up |
| **Liveness threshold** | `checkServer.*`, `recreateCerts.*`, `certsValidation.*` | How long a checker may stay silent before being declared dead |

The first is passed into `Monitore` from `main.go`, the second is computed inside
`checkMonitorXXX` on every check. The threshold must follow the checker schedule: if a
checker runs every 30 seconds, declaring it dead after 5 seconds of silence is wrong.

To avoid confusion, the `Monitore` parameters are named `tcpPollInterval`,
`recreateCertsPollInterval` and `checkValidCertsPollInterval` - they refer to polling.

### Display

The `Monitors.CheckTCPStatus`, `RecreateCertStatus` and `CheckValidCertsStatus` flags are
read by `overviewController` and shown on the dashboard. Access to the struct is guarded
by the `MutexMonitor` mutex.

## How to verify

```bash
# Monitor logs
grep "CheckMonitor" logs/tlss.log | tail -20

# Expected: "Checker is working" for each of the three
```

The reaction to a failure can be checked by raising a checker interval in the
configuration above its threshold and restarting the application - the monitor will
start logging `Checker is not working`.

```bash
# Freshness of days_left
sqlite3 db/database.db "
  SELECT common_name, cert_expire_time, days_left, cert_status
  FROM certs WHERE cert_status IN (0,1) ORDER BY days_left LIMIT 5;"

# Server status
sqlite3 db/database.db "SELECT hostname, server_status FROM server;"
```
