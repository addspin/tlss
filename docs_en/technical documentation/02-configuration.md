# 02. Configuration

Read through **viper** from `config.yaml`. The file is looked up in the working
directory and next to the executable. If it is missing, it is created from the embedded
`configInit.yaml`, which means **a new key has to be added to both files**: otherwise a
clean installation will end up with an empty value.

All keys are read directly by string path (`viper.GetString("CAcrl.subCACrlURL")`); there
is no configuration struct in Go. That means **a typo in a key name will not raise an
error** - viper silently returns the zero value. A way to check is given at the end of
this section.

## app - network parameters

```yaml
app:
  port: 43000          # UI and REST API
  est_port: 43001      # EST (always TLS, mTLS)
  crl_port: 8080       # CRL and OCSP
  crl_protocol: http   # http | https
  hostname: tlss.lv.local
  protocol: https      # http | https - UI only
  certFile: https/tlss.lv.local.pem
  keyFile: https/tlss.lv.local.key
```

`hostname` is used as the bind address for all three listeners. `certFile`/`keyFile` are
shared by the UI and EST; if they are not set, the EST server does not start (a warning
goes into the log), and the UI fails on `protocol: https`.

## logging

```yaml
logging:
  level: info    # debug | info | warn | error
  format: text   # text | json
  output: stdout # stdout | file | both
  file: logs/tlss.log
```

Handled in `utils/logger.go`, configures the global `slog`.

## login - initial setup

```yaml
login:
  authConfig: true   # true - take the credentials from here, false - ask in the console
  username: admin
  password: ...
  salt: ...
```

Used **only on the first run**, when the `secret_key` table is empty: a key is derived
from the password and salt (PBKDF2) and encrypts the generated master key. On
subsequent runs the same values are needed to decrypt it. In production it is sensible
to set `authConfig: false`, so the password is entered manually and never stored in the
file.

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

Only `sub_ca_tlss.commonName` is read - during Sub CA reissuance. The
`root_ca_tlss.commonName` key is unused in code: the root CA common name is entered in
the UI form.

## CAcrl - CRL distribution points

```yaml
CAcrl:
  subCACrlURL: http://tlss.lv.local:8080/api/v1/crl/subca/pem
  rootCACrlURL: http://tlss.lv.local:8080/api/v1/crl/rootca/pem
  unit: hours
  updateInterval: 24
```

Per RFC 5280 every certificate references the CRL of **its own issuer**, so the
addresses differ and are not interchangeable:

| Key | Goes into the CDP of | Who signs that CRL |
|---|---|---|
| `subCACrlURL` | end-entity certificates (server, client, EST) | Sub CA |
| `rootCACrlURL` | Sub CA certificates | Root CA |

`unit` plus `updateInterval` define both the regeneration period and the `nextUpdate`
window inside the CRL.

## CAocsp - OCSP endpoint

```yaml
CAocsp:
  url: http://tlss.lv.local:8080/ocsp
  unit: hours
  responseValidity: 24   # nextUpdate in the response
```

Here the address is **shared across the whole hierarchy**, unlike CRL. The responder
identifies the issuer not by URL but from `IssuerNameHash`/`IssuerKeyHash` in the request
itself (RFC 6960 §4.1.1), so a single endpoint serves both the Core CA and external CAs.

## CApath / ca_tlss - where the CA is stored

```yaml
CApath:
  db: true      # store the CA in the database
  server: false # store the CA in files
ca_tlss:
  path_cert: ./root_ca_tlss/root_ca_tlss.pem
  path_key: ./root_ca_tlss/root_ca_tlss.key
```

The primary mode is `db: true`. The paths in `ca_tlss` act as a fallback: if the Root CA
is not found in the database, `GenerateRSASubCA` and the Root CA CRL generator will try
to read it from files.

## add_server - SSH

```yaml
add_server:
  unit: seconds
  waitingToConnect: 3
```

The TCP connection timeout used when checking server availability and when delivering
certificates over SSH. The value matters: without it an unresponsive host would block
the checker for tens of seconds (the system TCP timeout).

## Checkers

```yaml
checkServer:        { unit: seconds, checkServerInterval: 10 }     # TCP port polling
certsValidation:    { unit: seconds, certsValidationInterval: 30 } # days_left recalculation
recreateCerts:      { unit: seconds, recreateCertsInterval: 5 }    # reissuing expired certs
```

## monitor - supervising the checkers

```yaml
monitor:
  unitTCP: seconds
  TCPInterval: 5
  unitRecreateCerts: seconds
  RecreateCertsInterval: 3
  unitCheckValidCerts: seconds
  CheckValidCertsInterval: 10
```

This is the **monitor polling frequency**, not the checker intervals. The "checker is
not responding" threshold is computed inside the monitor from the corresponding checker
settings as `interval x 1.5`. The distinction is easy to mix up - details in
[10-checkers.md](10-checkers.md).

## overview

```yaml
overview:
  checkClientExpireDaysLeft: 30
  checkServerExpireDaysLeft: 30
```

The thresholds at which a certificate is highlighted on the dashboard as expiring.

## est / estCSRAttrs

```yaml
est:
  cert_ttl_enrollment: 365   # lifetime of a certificate issued through simpleenroll
estCSRAttrs:
  rfc9908: true              # true - RFC 9908, false - RFC 7030
```

`cert_ttl_enrollment` applies only to the initial issuance over Basic Auth. During
`simplereenroll` the lifetime is taken from the `ttl` field of the previous certificate.

`rfc9908` switches the `/csrattrs` response between the original RFC 7030 structure and
the newer one from RFC 9908 - different clients understand different variants. See
[08-est.md](08-est.md).

## Verifying configuration integrity

Since a typo does not cause an error, it is worth periodically checking that every key
read by the code is present in the configuration:

```bash
# Keys the code reads
grep -rhoE 'viper\.Get[A-Za-z]+\("[^"]+"\)' --include="*.go" . \
  | grep -oE '"[^"]+"' | tr -d '"' | sort -u > /tmp/code_keys.txt

# Keys present in the configuration
awk '/^[a-zA-Z_][a-zA-Z0-9_]*:[[:space:]]*(#.*)?$/ { s=$1; sub(/:.*/,"",s); next }
     /^  [a-zA-Z_]/ { k=$1; sub(/:.*/,"",k); if (s!="") print s"."k }' \
  config.yaml | sort -u > /tmp/cfg_keys.txt

echo "Read by code, missing in config:"; comm -23 /tmp/code_keys.txt /tmp/cfg_keys.txt
echo "Present in config, unused by code:"; comm -13 /tmp/code_keys.txt /tmp/cfg_keys.txt
```

The first list should be empty. The second one may legitimately contain a single
entry - `root_ca_tlss.commonName`.

The same check is useful for `configInit.yaml`: any divergence from `config.yaml` means
a fresh installation will get an incomplete configuration.
