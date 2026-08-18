# 03. Database

A single SQLite database, path from `database.path`. Schemas are defined in the `models`
package as `Schema*` constants and executed on every start through
`CREATE TABLE IF NOT EXISTS`. Database access goes through `sqlx`, with mapping by
`db:"..."` tags.

## Tables

| Table | Purpose | Model |
|---|---|---|
| `secret_key` | AES master key, encrypted with the administrator password | `models.SchemaKey` |
| `users` | UI accounts | `models.UsersData` |
| `server` | Remote servers for SSH certificate delivery | `models.SchemaServer` |
| `ssh_key` | SSH keys used to connect to servers | `models.SchemaSSHKey` |
| `ca_certs` | Own Root and Sub CAs | `models.SchemaCA` |
| `ca_certs_ext` | Uploaded external CAs | `models.SchemaCAExt` |
| `entity_ca` | Groups of external CAs | `models.SchemaEntityCA` |
| `certs` | Server certificates | `models.SchemaCerts` |
| `entity` | Entities for client certificates | `models.SchemaEntity` |
| `oid` | Custom OIDs | `models.SchemaOID` |
| `user_certs` | Client certificates | `models.SchemaUserCerts` |
| `est_users` | Accounts for EST Basic Auth | `models.SchemaESTUser` |
| `est_certs` | Certificates issued through EST or the EST UI | `models.SchemaESTCerts` |
| `crl` | Generated CRLs (Sub, Root, Bundle) | `models.SchemaCRL` |
| `sub_ca_crl_info`, `root_ca_crl_info` | CRL counters and metadata | `models.SchemaCrlInfo*` |
| `api_keys` | REST API access keys | `models.SchemaAPIKey` |

## Common conventions

The three certificate tables (`certs`, `user_certs`, `est_certs`) and `ca_certs`
deliberately use identical column names - this lets the checkers, CRL and OCSP work
with them uniformly.

| Column | Meaning |
|---|---|
| `serial_number` | Serial number in **uppercase hex, without leading zeros** |
| `public_key` | Certificate in PEM |
| `private_key` | Private key in PEM, encrypted with AES-256-GCM |
| `cert_create_time`, `cert_expire_time` | Time in RFC 3339 with local offset |
| `days_left` | Days until expiry, recalculated by the checker |
| `cert_status` | `0` valid, `1` expired, `2` revoked |
| `data_revoke` | Revocation time (RFC 3339) or an empty string |
| `reason_revoke` | Revocation reason: `keyCompromise`, `superseded`, `unspecified`, ... |
| `signing_ca_id` | `0` signed by our own Sub CA, `>0` the `entity_ca.id` of an external CA |

### Serial number format

`strings.ToUpper(serialNumber.Text(16))` is used everywhere. Leading zeros are not
added, so the string length may be odd. This matters when comparing with `openssl`
output: openssl pads the number to an even digit count, so `3CEF...` in the database
shows up as `03CEF...` in the CRL. The verification scripts account for both variants.

### Time format

Every timestamp is written as `time.Now().Format(time.RFC3339)` - with the **local zone
offset**, for example `2026-08-14T09:45:12+04:00`. In CRL and OCSP the same moment is
rendered in UTC (`Aug 14 05:45:12 2026 GMT`), because RFC 5280 §5.1.2.6 requires Zulu.
This is not a mismatch, just two representations of one instant.

### The meaning of `signing_ca_id`

The key field for separating areas of responsibility:

| Value | Who signed | CRL | OCSP |
|---|---|---|---|
| `0` | our own Sub CA | included in the Sub CA CRL | answered by the Sub CA |
| `>0` | the external CA with that `entity_ca.id` | **not included** | answered by the external CA |

Certificates of external CAs are deliberately excluded from the CRL: our CRL is signed
by our own Sub CA and does not apply to a foreign hierarchy - a client would reject it.
Over OCSP they are served correctly, because the response is signed by the key of the
same external CA. Details in [06-crl.md](06-crl.md) and [07-ocsp.md](07-ocsp.md).

## Relations

```
entity_ca ──1:N──> ca_certs_ext        external CA group and its certificates
    │
    └──── signing_ca_id ────> certs / user_certs / est_certs

entity ────1:N────> user_certs         entity and its client certificates
server ────1:N────> certs              server and its certificates
ssh_key ───N:1────  server             the key used to reach the server
est_users ─1:N────> est_certs          EST user and the certificates issued to them
```

There are almost no foreign keys at the SQLite level (apart from `est_certs.est_user_id`);
integrity is maintained by the code.

## Migrations

They run in `main.go` right after the tables are created. The approach is simple:
`ALTER TABLE ADD COLUMN` without any check, and the "duplicate column" error is
ignored - which makes the operation idempotent.

```go
db.Exec("ALTER TABLE api_keys ADD COLUMN key_status INTEGER DEFAULT 0")
db.Exec("ALTER TABLE certs ADD COLUMN signing_ca_id INTEGER DEFAULT 0")
db.Exec("ALTER TABLE user_certs ADD COLUMN signing_ca_id INTEGER DEFAULT 0")
db.Exec("ALTER TABLE ssh_key ADD COLUMN passphrase TEXT NOT NULL DEFAULT ''")
```

**Important:** a new column has to be added both to the `Schema*` constant in `models`
and to the migrations. The schema covers clean installations, the migration covers
existing databases. Adding it only to the schema leaves older databases without the
column and queries will fail.

The `est_certs` table appeared later than the others, and its `san`, `private_key`,
`password` and `ttl` columns were added manually - there are no matching `ALTER TABLE`
statements in `main.go`, only the full schema. Databases created before that point need
the migration applied by hand.

## Useful queries

```bash
# Certificate state by status
sqlite3 db/database.db "
  SELECT 'certs' t, cert_status, COUNT(*) FROM certs GROUP BY cert_status
  UNION ALL SELECT 'user_certs', cert_status, COUNT(*) FROM user_certs GROUP BY cert_status
  UNION ALL SELECT 'est_certs', cert_status, COUNT(*) FROM est_certs GROUP BY cert_status;"

# What was signed by external CAs
sqlite3 db/database.db "SELECT signing_ca_id, COUNT(*) FROM certs GROUP BY signing_ca_id;"

# Active CAs
sqlite3 db/database.db "SELECT id, type_ca, common_name, cert_status FROM ca_certs ORDER BY id;"

# Find a certificate by serial number across all tables
S=3CEF5CDBA445C409C36D22718667676
sqlite3 db/database.db "
  SELECT 'certs', common_name, cert_status FROM certs WHERE serial_number='$S'
  UNION ALL SELECT 'user_certs', common_name, cert_status FROM user_certs WHERE serial_number='$S'
  UNION ALL SELECT 'est_certs', common_name, cert_status FROM est_certs WHERE serial_number='$S';"
```
