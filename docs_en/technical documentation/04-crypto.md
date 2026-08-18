# 04. Cryptography (the `crypts` package)

This is where all key and certificate handling lives. The cryptography is the Go
standard library plus `golang.org/x/crypto` for SSH, bcrypt and PBKDF2.

## Package files

| File | Purpose |
|---|---|
| `aes.go` | Encryption of private keys and passwords (AES-256-GCM) |
| `pbkdf2.go` | Key derivation from the administrator password |
| `rsaRootCA.go` | Root CA generation |
| `rsaSubCA.go` | Intermediate CA generation |
| `rsaExtractCA.go` | Cache of the active Sub CA (`ExtractCA`) |
| `extCA.go` | Parsing uploaded external CAs, key matching, signer selection |
| `rsa.go`, `ecdsa.go`, `ed25519.go` | Issuance and reissuance of server certificates |
| `rsaUser.go`, `ecdsaUser.go`, `ed25519User.go` | The same for client certificates |
| `rsaEST.go`, `ecdsaEST.go`, `ed25519EST.go` | The same for EST certificates issued through the UI |
| `estSign.go` | Signing a CSR received over the EST protocol |
| `estClientCAPool.go` | Trusted CA pool for verifying client certificates in mTLS |
| `san.go` | Parsing the SAN string into DNS / IP / email |
| `rsaSSH.go` | SSH key generation |
| `saveOnServer.go` | Certificate delivery to a remote server over SSH |
| `apiKey.go` | API key generation |

## Protecting private keys

### Two-level scheme

```
administrator password + salt
          │ PBKDF2-SHA256, 100,000 iterations, 32 bytes
          ▼
      encryption key ──── decrypts ───> secret_key.key_data
                                                │
                                                ▼
                                        master key (32 bytes)
                                                │ AES-256-GCM
                                                ▼
                    certificate private keys, SSH keys, PKCS#12
                    passwords - in the private_key / password columns
```

The PBKDF2 parameters are set in `crypts/pbkdf2.go`: `Iterations = 100000`,
`KeySize = 32`, SHA-256.

The master key lives in process memory in `crypts.AesSecretKey.Key` and is used by every
component: certificate issuance, CRL, OCSP and SSH delivery.

### AES-256-GCM

`crypts/aes.go` uses GCM - authenticated encryption: tampering with the ciphertext in
the database is detected during decryption instead of yielding a corrupted key.

### Consequences

- The database file gives no access to any private key without the administrator password.
- Losing the password means irreversibly losing all keys - there is no backup copy of the
  master key by design.
- Every signing operation requires the process to be running and unlocked; after a
  restart the password is needed again (or taken from `login.authConfig`).

## CA hierarchy

```
Root CA  (self-signed, RSA)
   └── Sub CA  (RSA)
         ├── server certificates   (certs)
         ├── client certificates   (user_certs)
         └── EST certificates      (est_certs, signing_ca_id = 0)

External CAs (ca_certs_ext, grouped by entity_ca)
   └── certificates with signing_ca_id = entity_ca.id
```

### Certificate profiles

| Type | KeyUsage | ExtKeyUsage | IsCA |
|---|---|---|---|
| Root CA | CertSign, CRLSign, DigitalSignature | - | yes, `MaxPathLen: 1` |
| Sub CA | CertSign, CRLSign, DigitalSignature | ClientAuth, ServerAuth | yes, `MaxPathLen: 0` |
| Server | DigitalSignature, KeyEncipherment | ServerAuth, ClientAuth | no |
| Client | DigitalSignature, KeyEncipherment | ClientAuth | no |
| EST | DigitalSignature, KeyEncipherment | ClientAuth | no |

Revocation checking extensions:

| Type | CDP (RFC 5280 §4.2.1.13) | AIA / OCSP (§4.2.2.1) |
|---|---|---|
| Root CA | none (self-signed, validated through the trust store) | none |
| Sub CA | `CAcrl.rootCACrlURL` | `CAocsp.url` |
| End-entity | `CAcrl.subCACrlURL` | `CAocsp.url` |

### The `ExtractCA` cache and its reset

`crypts.ExtractCA` holds the parsed certificate and key of the active Sub CA so they do
not have to be decrypted on every issuance. It is filled at startup and lazily whenever
the field is `nil`.

The critical part: when the Sub CA is reissued the cache **must** be reset, otherwise
every subsequent certificate would be signed with the old, already revoked key, and its
AKI would not match the new CRL and OCSP responses. The reset happens at the end of
`GenerateRSASubCA`:

```go
ExtractCA.SubCAcert = nil
ExtractCA.SubCAKey = nil
```

The symptom when the reset is missing: the UI shows updated dates, but
`openssl x509 -text` reports the old issuer and `openssl verify` cannot build the chain.

## External CAs

The user uploads an arbitrary set of PEM files (certificates and keys). Parsing in
`extCA.go` happens in four steps:

1. **`ParsePEMFiles`** - parses all PEM blocks, splitting them into certificates and keys.
2. **`MatchKeysToCerts`** - matches a key to a certificate by comparing **public keys**,
   not file names. A key may be absent - then the CA is only usable for building the
   chain, not for signing.
3. **`DetermineCAType`** - decides between Root and Sub:
   - self-signed (`Subject == Issuer` and `AKI == SKI`) -> Root
   - `IsCA` and `Subject != Issuer` -> Sub
4. **`BuildCAExtRecords`** - encrypts the keys and stores the records in `ca_certs_ext`.

### Choosing the signer

`ExtractExtCA(db, entityCAId)` decides which CA from the group actually signs:

```sql
SELECT * FROM ca_certs_ext
WHERE entity_ca_id = ? AND private_key != '' AND cert_status = 0
ORDER BY CASE type_ca WHEN 'Sub' THEN 1 WHEN 'Intermediate' THEN 2 WHEN 'Root' THEN 3 ELSE 4 END
```

The first record is taken - that is, the lowest CA in the hierarchy that has a key. This
matches common practice: the Root only signs intermediates, while end-entity
certificates are issued by the Sub CA.

Type detection and signer selection have weak spots with non-standard hierarchies, for
example when the Root and Sub CA share the same CommonName, or when a group holds
several active CAs of the same type.

## Algorithms and key lengths

| Algorithm | Allowed values | Limitations |
|---|---|---|
| RSA | 2048, 4096, 8192 | The only option for the Root and Sub CA |
| ECDSA | 256, 384, 521 (P-224 supported by the code but not the UI) | |
| ED25519 | fixed 256 | Cannot sign OCSP responses |

About ED25519: `golang.org/x/crypto/ocsp` in `CreateResponse` supports only RSA and
ECDSA. Own CAs are always RSA, so this is not an issue there; but an external ED25519 CA
will not be able to answer over OCSP - the request ends with `internalError`.

## SAN

`crypts/san.go` parses a comma-separated string and sorts the values by type: IP
addresses are detected with `net.ParseIP`, values containing `@` are treated as email,
everything else becomes a DNS name. The Common Name is added to the DNS names
automatically, since modern clients ignore CN for hostname verification (RFC 6125).

## SSH delivery

`saveOnServer.go` connects through `golang.org/x/crypto/ssh` and copies the certificate
and key into the `server.cert_config_path` directory. The key comes from `ssh_key`
(decrypted with the master key), and the connection timeout from
`add_server.waitingToConnect`.

## How to verify

```bash
# Profile of an issued certificate
sqlite3 db/database.db "SELECT public_key FROM certs ORDER BY id DESC LIMIT 1;" \
  | openssl x509 -noout -text | grep -A2 -E "Key Usage|Extended Key Usage|CRL Distribution|Authority Information"

# The certificate AKI against the SKI of the active Sub CA
sqlite3 db/database.db "SELECT public_key FROM ca_certs WHERE type_ca='Sub' AND cert_status=0;" \
  | openssl x509 -noout -text | grep -A1 "Subject Key Identifier"

# Chain validation
sqlite3 db/database.db "SELECT public_key FROM ca_certs WHERE type_ca='Root' AND cert_status=0;" > /tmp/root.pem
sqlite3 db/database.db "SELECT public_key FROM ca_certs WHERE type_ca='Sub'  AND cert_status=0;" > /tmp/sub.pem
cat /tmp/root.pem /tmp/sub.pem > /tmp/chain.pem
sqlite3 db/database.db "SELECT public_key FROM certs ORDER BY id DESC LIMIT 1;" > /tmp/cert.pem
openssl verify -CAfile /tmp/chain.pem /tmp/cert.pem
```
