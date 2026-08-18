# TLSS - technical documentation

TLSS is a certificate authority (PKI) with a web interface: it issues server, client
and EST certificates, publishes CRLs, answers OCSP requests and can deploy certificates
to remote servers over SSH. All state lives in a single SQLite database, private keys
are stored encrypted.

## Sections

| Document | Contents |
|---|---|
| [01-architecture.md](01-architecture.md) | Processes, network listeners, startup order, component relationships |
| [02-configuration.md](02-configuration.md) | `config.yaml` section by section, where each key is read |
| [03-database.md](03-database.md) | Tables, column meaning, relations, migrations |
| [04-crypto.md](04-crypto.md) | The `crypts` package: CA hierarchy, algorithms, key encryption, SSH |
| [05-certificates.md](05-certificates.md) | Lifecycle: issuance, reissuance, revocation, rollback, export |
| [06-crl.md](06-crl.md) | CRL generation and publication, RFC 5280 |
| [07-ocsp.md](07-ocsp.md) | OCSP responder, RFC 6960 and the RFC 5019 profile |
| [08-est.md](08-est.md) | EST server, RFC 7030, mTLS, EST user management |
| [09-api.md](09-api.md) | REST API, API key authentication, scopes |
| [10-checkers.md](10-checkers.md) | Background checkers and the liveness monitor |
| [11-web-ui.md](11-web-ui.md) | Templates, HTMX, sessions, static assets |
| [12-testing.md](12-testing.md) | Test scripts and what exactly they verify |

## Stack

| Library | Version | Role |
|---|---|---|
| `github.com/gofiber/fiber/v3` | 3.2.0 | HTTP framework (three independent applications) |
| `github.com/gofiber/template/html/v2` | 2.1.3 | Go template rendering |
| `github.com/jmoiron/sqlx` | 1.4.0 | Database access, mapping into structs |
| `github.com/mattn/go-sqlite3` | 1.14.22 | SQLite driver (cgo) |
| `github.com/spf13/viper` | 1.20.0-alpha.6 | Configuration reading |
| `go.mozilla.org/pkcs7` | 0.9.0 | PKCS#7 for EST (`cacerts`, enroll responses) |
| `golang.org/x/crypto` | 0.52.0 | OCSP, SSH, bcrypt, PBKDF2 |
| `software.sslmate.com/src/go-pkcs12` | 0.5.0 | Export to PKCS#12 (`.p12`) |

Certificate cryptography relies on the Go standard library (`crypto/x509`, `crypto/rsa`,
`crypto/ecdsa`, `crypto/ed25519`); no third-party PKI libraries are used.

## Standards

| RFC | Where it applies |
|---|---|
| **RFC 5280** | X.509 and CRL profile: CDP, AIA, KeyUsage extensions, revocation reason codes |
| **RFC 6960** | OCSP: request and response format, issuer resolution, statuses |
| **RFC 5019** | Lightweight OCSP profile: mandatory `nextUpdate`, `unauthorized`, caching |
| **RFC 7030** | EST: `cacerts`, `simpleenroll`, `simplereenroll`, `csrattrs` |
| **RFC 9908** | Alternative `csrattrs` structure (enabled by a configuration flag) |
| **RFC 2986** | PKCS#10 - CSR parsing during EST issuance |
| **RFC 5652** | PKCS#7/CMS - the container for EST responses |
| **RFC 7292** | PKCS#12 - exporting a certificate together with its key |
| **RFC 3339** | Time format across all tables |

## A quick tour of the code

The entry point is [`main.go`](../../main.go): it reads the configuration, creates
tables, applies migrations, decrypts the master key, starts background tasks and three
HTTP listeners.

Routes are collected in [`routes/routes.go`](../../routes/routes.go) - four
registration functions matching the four areas of responsibility: the main application,
CRL, OCSP and EST.
