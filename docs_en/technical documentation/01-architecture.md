# 01. Architecture

## One process, three HTTP applications

The application starts three independent Fiber instances on different ports. The split
is not cosmetic: each listener has its own authentication model and its own TLS
requirements, and combining them on a single port is impossible.

| Application | Port (config) | Protocol | Authentication | Purpose |
|---|---|---|---|---|
| **UI + API** | `app.port` (43000) | per `app.protocol` | Sessions (UI), API key (`/api/v1/*`) | Web interface and REST API |
| **CRL + OCSP** | `app.crl_port` (8080) | per `app.crl_protocol` | none | CRL publication, OCSP responses |
| **EST** | `app.est_port` (43001) | always TLS | Basic Auth and mTLS | EST protocol (RFC 7030) |

### Why CRL and OCSP are separate and served over HTTP

RFC 5280 §4.2.1.13 and RFC 5019 §5 assume that revocation checking endpoints are
reachable over plain HTTP. If CDP and AIA pointed at HTTPS, a circular dependency would
appear: to validate a certificate the client must establish a TLS connection, which
requires validating a certificate. Hence a separate listener that is unencrypted by
default - the data there is signed by the CA and needs no confidentiality.

### Why EST is separate

`simplereenroll` authenticates the client with a previously issued certificate, which
means mTLS. The client certificate is requested during the TLS handshake, when the
server does not yet know the request URL, so enabling mTLS "for one route only" is not
possible. EST therefore lives on its own port with `tls.VerifyClientCertIfGiven`, while
the UI on the main port never asks for client certificates.

Details in [08-est.md](08-est.md).

## Startup order

[`main.go`](../../main.go) performs strictly sequential steps:

1. **Configuration.** If there is no `config.yaml` next to the executable, it is created
   from the embedded `configInit.yaml` (`//go:embed`) and then read through viper.
2. **Logging.** `utils.SetupSlogLogger()` configures `slog` from the `logging` section.
3. **Database.** SQLite is opened, the `db`, `root_ca_tlss`, `https`, `crlFile` and
   `logs` directories are created.
4. **Schema.** Every `CREATE TABLE IF NOT EXISTS` from the `models` package runs,
   followed by idempotent `ALTER TABLE` migrations (see [03-database.md](03-database.md)).
5. **Master key.** If the `secret_key` table is empty, a 32-byte key is generated,
   encrypted with the administrator password and stored. Otherwise it is decrypted and
   kept in `crypts.AesSecretKey.Key` in process memory for the whole lifetime.
6. **SSH key.** If missing, a `Default` key is created for connecting to servers.
7. **Sub CA into memory.** `crypts.ExtractCA.ExtractSubCA(db)` caches the active Sub CA.
8. **Background tasks** (five goroutines, see below).
9. **Listeners.** CRL/OCSP and EST start in goroutines, the UI application blocks the
   main goroutine.

## Background tasks

| Goroutine | Interval from config | What it does |
|---|---|---|
| `check.Monitore` | `monitor.*` | Watches that the other checkers are alive |
| `crl.StartCombinedCRLGeneration` | `CAcrl.updateInterval` | Periodically regenerates the CRLs |
| `checkTCP.TCPPortAvailable` | `checkServer.*` | Checks server reachability over TCP |
| `check.CheckValidCerts` | `certsValidation.*` | Recalculates `days_left`, marks expired entries |
| `check.RecreateCerts` | `recreateCerts.*` | Reissues expired certificates flagged with `recreate` |

Details in [10-checkers.md](10-checkers.md).

## Package map

```
main.go                     entry point, initialization, listener startup
├── routes/                 route registration for all four areas
├── controllers/            HTTP handlers grouped by domain
│   ├── serverCertControllers/   server certificates, CRL endpoints
│   ├── usersCertControllers/    client certificates, entities, OIDs
│   ├── estControllers/          EST protocol and EST management UI
│   ├── caControllers/           Root/Sub CA, external CAs
│   ├── ocspControllers/         OCSP endpoint
│   ├── apiKeyControllers/       API key issuance and revocation
│   ├── sshControllers/          SSH keys for server delivery
│   ├── loginControllers/        login and logout
│   ├── overviewController/      dashboard summary
│   └── certInfoController/      inspection of an uploaded certificate
├── crypts/                 all cryptography: CA, issuance, AES, SSH, PBKDF2
├── crl/                    CRL construction
├── ocsp/                   OCSP response construction
├── check/                  background checkers and monitor
├── middleware/             sessions, API keys, EST Basic/Cert auth
├── models/                 structs and SQL table schemas
├── utils/                  logger, interval conversion
├── template/               HTML templates (embedded via go:embed)
├── static/                 CSS, JS, fonts, icons (embedded)
└── tests/                  bash scripts checking CRL, OCSP, EST, consistency
```

## Component relationships

```
                          ┌──────────────┐
                          │  config.yaml │
                          └──────┬───────┘
                                 │ viper
                    ┌────────────┴─────────────┐
                    ▼                          ▼
            ┌──────────────┐          ┌─────────────────┐
            │  controllers │          │ check (checkers)│
            └───────┬──────┘          └────────┬────────┘
                    │                          │
                    ▼                          ▼
            ┌───────────────────────────────────────┐
            │              crypts                   │
            │  ExtractCA (Sub CA cache), Aes (keys) │
            └───────┬──────────────────────┬────────┘
                    │                      │
        ┌───────────┴─────┐         ┌──────┴──────┐
        ▼                 ▼         ▼             ▼
   ┌─────────┐      ┌─────────┐ ┌───────┐   ┌──────────┐
   │  crl    │      │  ocsp   │ │ models│   │  SQLite  │
   └─────────┘      └─────────┘ └───────┘   └──────────┘
```

Key points of coupling:

- **`crypts.AesSecretKey.Key`** - the master key in memory. Without it no private key
  can be decrypted, so certificate issuance, CRL, OCSP and SSH delivery all depend on it.
- **`crypts.ExtractCA`** - the cache of the active Sub CA (certificate plus key). It is
  filled at startup and **reset** when the Sub CA is reissued in `GenerateRSASubCA`.
  Without the reset new certificates would be signed with a stale key.
- **`models`** - the single place where SQL schemas are described; every package uses
  the same structs for mapping.

## Storage and encryption

All state lives in one SQLite file (`database.path`). Private keys of every certificate,
PKCS#12 container passwords and private SSH keys are stored encrypted with AES-256-GCM
under the master key. The master key itself is kept in `secret_key`, encrypted with the
administrator password derived through PBKDF2.

The consequence: **the database file is useless without the administrator password** -
not a single private key can be extracted from it. Recovery is equally impossible:
losing the password means losing all keys.

Details in [04-crypto.md](04-crypto.md).
