# 02. Preparing for production

The default configuration is meant for a quick start and local testing. Before real
use it has to be adjusted - below is what exactly and why.

## Must change

### `login.authConfig` - keep the password out of the file

```yaml
login:
  authConfig: false   # was true
```

With `true` the login and password are read from `config.yaml`, which means they sit
on disk in plain text next to the database. With `false` the application asks for them
in the console on every start and nothing is stored in the file.

Keep in mind: with `authConfig: false` an automatic restart requires manual input. If
the application runs as a service, you have to choose between convenience and keeping
the password on disk - there is no middle ground here.

### `app.hostname` - a real name

```yaml
app:
  hostname: pki.example.com
```

It is used as the bind address for all three listeners and must match the name in the
server certificate, otherwise clients will reject the connection.

### `app.protocol` and the TLS certificate

```yaml
app:
  protocol: https
  certFile: https/pki.example.com.pem
  keyFile: https/pki.example.com.key
```

By default the interface starts over HTTP. Production needs HTTPS: container passwords
and private keys travel through the interface.

The same files are used by the EST server. If they are not set, EST will not start and
a warning goes into the log.

### CRL and OCSP addresses

```yaml
CAcrl:
  subCACrlURL: http://pki.example.com:8080/api/v1/crl/subca/pem
  rootCACrlURL: http://pki.example.com:8080/api/v1/crl/rootca/pem

CAocsp:
  url: http://pki.example.com:8080/ocsp
```

These addresses are **embedded into every issued certificate** (the CDP and AIA
extensions) and must be reachable by clients exactly as written. Changing them after
issuance is pointless: already issued certificates keep the old value.

That is why the addresses should be settled **before** creating the CA and issuing
certificates.

Keep them on **HTTP rather than HTTPS**: to validate a certificate the client has to
download a CRL or fetch an OCSP response, and if that required a TLS connection you
would get a circular dependency. The data is signed by the CA and needs no encryption.

### Password and salt

```yaml
login:
  password: ...
  salt: ...
```

The values shipped in the configuration template are examples. Even with
`authConfig: false`, make sure no default values are left in the file.

## Worth reviewing

### Background task intervals

The defaults are in seconds and meant for demonstration - in production such a
frequency only adds load:

```yaml
checkServer:
  unit: seconds
  checkServerInterval: 10        # -> minutes, 1-5

certsValidation:
  unit: seconds
  certsValidationInterval: 30    # -> minutes, 10-30

recreateCerts:
  unit: seconds
  recreateCertsInterval: 5       # -> minutes, 5-15
```

The monitor intervals (`monitor.*`) define how often checker liveness is verified. It
makes sense to keep them more frequent than the checkers themselves, but also move
them to minutes.

Important: the "checker is not responding" thresholds are derived from the checker
settings, so raising a checker interval raises its threshold automatically - nothing
else has to be adjusted.

### CRL update period

```yaml
CAcrl:
  unit: hours
  updateInterval: 24
```

The value goes into the `nextUpdate` field of the CRL: clients treat the list as valid
for exactly that long. A day is a reasonable balance. Lowering it to hours only makes
sense if revocations are frequent and propagation speed matters.

Remember that the CRL is regenerated **immediately** on every revocation and rollback,
so the interval only affects scheduled updates.

### OCSP response lifetime

```yaml
CAocsp:
  responseValidity: 24   # hours
```

Defines `nextUpdate` in the response and the caching time on proxies. The lower the
value, the faster clients learn about a revocation, and the higher the load on the
responder.

### Lifetime of certificates issued over EST

```yaml
est:
  cert_ttl_enrollment: 365
```

Applies to the initial issuance through `simpleenroll`. For devices that renew
automatically a short lifetime makes sense - 90 days or less.

### Logging

```yaml
logging:
  level: info      # debug only for troubleshooting
  format: json     # easier for log collectors
  output: both     # stdout + file
  file: logs/tlss.log
```

Log rotation is not built in - with `output: file` or `both`, configure `logrotate` or
an equivalent, otherwise the file grows without limit.

## Operations

**Backups.** Copy `db/database.db` and `config.yaml`. Without the administrator
password the data cannot be recovered from the database, so keep the password
separately and safely.

**Database access.** The file contains all private keys, encrypted as they are.
Directory permissions should be limited to the user the application runs as.

**Sessions live in memory.** Restarting the application logs everyone out - this is
normal and requires no action.
