# 05. Certificate lifecycle

Three types of end-entity certificates, each with its own table and its own set of
controllers, but sharing the same states and the same revocation mechanism.

| Type | Table | Attached to | Controllers |
|---|---|---|---|
| Server | `certs` | a `server` record | `serverCertControllers` |
| Client | `user_certs` | an `entity` record | `usersCertControllers` |
| EST | `est_certs` | an `est_users` record | `estControllers` |

## States

```
        issuance
          │
          ▼
    ┌──────────┐   expired       ┌───────────┐
    │ 0 valid  │ ──────────────> │ 1 expired │
    └────┬─────┘   (checker)     └─────┬─────┘
         │                             │ recreate = 1
         │ revocation                  ▼
         │                       reissued -> 0 valid
         ▼
    ┌────────────┐   rollback
    │ 2 revoked  │ ─────────> 0 valid or 1 expired
    └────────────┘            (depending on days_left)
```

The transition to `expired` is performed by the `CheckValidCerts` checker, reissuance by
`RecreateCerts` (only when the record has the `recreate` flag). Revocation and rollback
are initiated by the user through the UI.

## Issuance

The overall flow is the same for all types, only the table and the field set differ:

1. The controller validates the input: algorithm from the allowed list (`RSA`, `ECDSA`,
   `ED25519`), a valid key length, presence of the mandatory fields.
2. The generator for that algorithm is called - for example `crypts.GenerateRSACertificate`.
3. The generator creates a key pair and a random 128-bit serial number.
4. An `x509.Certificate` template is assembled: Subject, SAN, KeyUsage/EKU according to
   the certificate type, CDP and AIA (see [04-crypto.md](04-crypto.md)).
5. The signer is resolved: with `SigningCAId = 0` the `ExtractCA` cache is used,
   otherwise `ExtractExtCA(db, SigningCAId)`.
6. `x509.CreateCertificate` signs it; the private key and the container password are
   encrypted with the master key.
7. The record is stored inside a transaction.

For server certificates with `SaveOnServer` enabled, delivery over SSH follows - if the
server is marked `offline`, the controller rejects the request upfront.

### Choosing the signing CA

Issuance forms contain a **Signing CA** field: "Core CA" (value `0`) or one of the
external CA groups (value `entity_ca.id`). The choice is stored in the `signing_ca_id`
column and drives the rest of the behaviour - which key signs, whether the certificate
lands in the CRL, and which CA answers over OCSP.

## Reissuance

Two different mechanisms that are easy to confuse:

### Automatic, on expiry

The `RecreateCerts` checker runs every `recreateCerts.recreateCertsInterval`, selects
records with `cert_status = 1 AND recreate = 1` and calls `Recreate*Certificate`. The
function generates a new key and certificate and **updates the existing row** by `id` -
the serial number changes, the `id` stays.

The `recreate` flag is set by a switch in the issuance form.

### Cascading, on CA reissuance

Triggered from the UI by revoking the Root or Sub CA. The sequence in
`RevokeCACertWithData`:

1. The current CA is marked revoked, and so is every certificate signed by it.
2. Previously revoked and expired records are deleted.
3. A new CA is generated - which also resets the `ExtractCA` cache.
4. Every valid certificate is reissued under the new CA: server, client and EST ones
   with `signing_ca_id = 0`. Processing runs in a goroutine pool with a mutex around
   database writes.
5. The CRL is regenerated.

Certificates of external CAs are not part of the cascade - they do not depend on our
hierarchy.

## Revocation and rollback

**Revocation** sets `cert_status = 2`, the time in `data_revoke` and the reason in
`reason_revoke`, then regenerates the CRL immediately.

**Rollback** puts the certificate back in service: it clears the revocation fields and
sets `cert_status` to `0` or `1` depending on `days_left`. The CRL is regenerated as
well, so the entry disappears from the list.

It is critical that `crl.CombinedCRL(db)` is called **after** `tx.Commit()`. The
generator opens its own SQLite connections and will not see an uncommitted transaction -
called before the commit it would publish the previous status.

## Export

`TakeCert` (server and client) and `TakeESTCert` provide three formats:

| Format | Contents |
|---|---|
| `zip` | certificate `.pem`, key `.key`, the Sub CA and Root CA chain |
| `pkcs12` | a `.p12` container, modern encryption |
| `pkcs12-legacy` | a `.p12` container, legacy algorithm - for macOS and older software |

The PKCS#12 container password is the one specified at issuance; it is stored encrypted
and decrypted only at export time.

For certificates issued by an external CA the chain is not included in the archive: the
application is not required to hold the full hierarchy of a foreign CA.

## Verification

```bash
# Profile and extensions
sqlite3 db/database.db "SELECT public_key FROM certs ORDER BY id DESC LIMIT 1;" \
  | openssl x509 -noout -text | less

# Status across all tables
sqlite3 db/database.db "
  SELECT 'certs' t, cert_status, COUNT(*) FROM certs GROUP BY cert_status
  UNION ALL SELECT 'user_certs', cert_status, COUNT(*) FROM user_certs GROUP BY cert_status
  UNION ALL SELECT 'est_certs', cert_status, COUNT(*) FROM est_certs GROUP BY cert_status;"

# Revocation status consistency between the database, CRL and OCSP
./tests/revocation/test_revocation.sh <SERIAL>
```
