# 09. REST API and authentication

The API lives on the main port (`app.port`) under the `/api/v1/` prefix. The handlers
are the same controllers that serve the UI, but with separate "API" functions returning
JSON.

## Authentication model

The application has three independent mechanisms, each in its own middleware:

| Mechanism | Middleware | Where it applies |
|---|---|---|
| Sessions | `AuthMiddleware` | Web interface |
| API key | `APIKeyAuth(scope)` | `/api/v1/*` |
| Basic / mTLS | `ESTBasicAuth`, `ESTCertAuth` | EST endpoints (a different port) |

`AuthMiddleware` is attached to the whole main application but skips the session check
for two prefixes - `/api/v1/` and `/.well-known/est/` - since those are protected by
their own middleware at the route level. It also lets public paths through:

```
/           /login      /overview      /cert_info
/api/v1/crl/{subca,rootca,bundleca}/{pem,der}
```

as well as static assets by extension (`.css`, `.js`, `.svg`, `.ico`, fonts).

There is also an **internal API key** - a random value generated at startup
(`crypts.GetInternalAPIKey`). It only exists in memory and is used by background tasks
to call the application's own endpoints.

## API keys

### How they are stored

The database holds not the key itself but `HMAC-SHA256(master key, key)` in hex. The
original value cannot be recovered from the database - it is shown exactly once, at
creation time.

```go
h := hmac.New(sha256.New, secret)   // secret = crypts.AesSecretKey.Key
```

HMAC rather than a plain hash was chosen because security is then tied to the master
key: even with a copy of the database an attacker cannot brute-force the key offline.

### Request validation

`APIKeyAuth(requiredScope)` performs:

1. Key extraction - from the `X-API-Key` header or `Authorization: Bearer <key>`.
2. HMAC computation and a lookup in `api_keys` by `key_hash` (a single database query,
   with no in-memory cache in between).
3. A check of `key_status` (`0` active, `1` expired) and the `expires_at` deadline.
4. A scope check: the `scopes` string is stored comma-separated and must contain the
   required value. An empty `scopes` means no permissions.
5. An update of `last_used` and the client IP.

Errors: `401` if the key is unknown, expired or disabled; `403` if the scope is
insufficient.

### Scopes

| Scope | Permissions |
|---|---|
| `read` | Retrieving lists |
| `write` | Creating certificates, servers, entities, generating CRLs |

## Endpoints

### Public - no authentication

| Method | Path | Response |
|---|---|---|
| GET | `/api/v1/crl/subca/pem` \| `/der` | Sub CA CRL |
| GET | `/api/v1/crl/rootca/pem` \| `/der` | Root CA CRL |
| GET | `/api/v1/crl/bundleca/pem` \| `/der` | Both CRLs one after another |

They are duplicated on the public port (`app.crl_port`) - that is where certificate CDPs
point. On the main port they are kept for compatibility.

### Require an API key

| Method | Path | Scope | Purpose |
|---|---|---|---|
| POST | `/api/v1/crl/bundleca/generate` | `write` | Force CRL regeneration |
| POST | `/api/v1/server/add_server` | `write` | Add a server |
| POST | `/api/v1/server/add_entity` | `write` | Add a server entity |
| POST | `/api/v1/server/add_certs` | `write` | Issue a server certificate |
| GET | `/api/v1/server/entity_server_list` | `read` | List of server entities |
| GET | `/api/v1/server/ssh_key_list` | `read` | List of SSH keys |
| GET | `/api/v1/users/entity_list` | `read` | List of client entities |
| GET | `/api/v1/users/oid_list` | `read` | List of OIDs |
| POST | `/api/v1/users/add_certs` | `write` | Issue a client certificate |

## Examples

```bash
KEY="<the key shown at creation time>"

# List of entities
curl -sk -H "X-API-Key: $KEY" \
  https://tlss.lv.local:43000/api/v1/users/entity_list

# The same through Bearer
curl -sk -H "Authorization: Bearer $KEY" \
  https://tlss.lv.local:43000/api/v1/server/entity_server_list

# Issuing a client certificate
curl -sk -X POST -H "X-API-Key: $KEY" -H "Content-Type: application/json" \
  -d '{
    "EntityId": 1,
    "Algorithm": "RSA",
    "KeyLength": 4096,
    "TTL": 365,
    "CommonName": "user@example.com",
    "CountryName": "RU",
    "StateProvince": "Udmurt Republic",
    "LocalityName": "Izhevsk",
    "Organization": "LV Inc.",
    "OrganizationUnit": "IT",
    "Email": "user@example.com",
    "Password": "container-password"
  }' \
  https://tlss.lv.local:43000/api/v1/users/add_certs

# CRL regeneration
curl -sk -X POST -H "X-API-Key: $KEY" \
  https://tlss.lv.local:43000/api/v1/crl/bundleca/generate
```

## Key management

The **API -> API keys** section in the UI. Creating a key asks for a name, scope and
TTL; the key value is shown once. Expired keys are marked by the `CheckValidCerts`
checker (`key_status = 1`) and stop working.
