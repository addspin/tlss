# 06. CRL - revocation lists

Implemented in the [`crl`](../../crl/crl.go) package, published by the
[`CRLController.go`](../../controllers/serverCertControllers/CRLController.go)
controller. Standard: **RFC 5280** (CRL profile, §5). Cryptography:
`crypto/x509.CreateRevocationList`.

## Two independent CRLs

Per RFC 5280 a CRL is signed by the same CA that issued the certificates listed in it.
Hence there are two lists, and they are not interchangeable:

| CRL | Signed by | Contains | Endpoint |
|---|---|---|---|
| **Sub CA CRL** | Sub CA | revoked end-entity certificates | `/api/v1/crl/subca/pem`, `/der` |
| **Root CA CRL** | Root CA | revoked Sub CA certificates | `/api/v1/crl/rootca/pem`, `/der` |
| **Bundle** | - | both blocks one after another | `/api/v1/crl/bundleca/pem`, `/der` |

The bundle is not a standard, just a convenience for manual inspection. **It must not be
used in a CDP**: `openssl crl` and most clients read only the first PEM block from a
file, so the second list is silently ignored. Certificate CDPs point at the specific
CRLs from `CAcrl.subCACrlURL` and `CAcrl.rootCACrlURL`.

## What goes into the Sub CA CRL

Three sources, all with the same condition - revoked and signed by **our** Sub CA:

```sql
SELECT ... FROM certs      WHERE cert_status = 2 AND signing_ca_id = 0
SELECT ... FROM user_certs WHERE cert_status = 2 AND signing_ca_id = 0
SELECT ... FROM est_certs  WHERE cert_status = 2 AND signing_ca_id = 0
```

The `signing_ca_id = 0` filter is essential. Without it the list would include
certificates issued by external CAs, producing a CRL signed by our Sub CA but carrying
foreign serial numbers. A client validating such a certificate would fetch the CRL by
its CDP, notice the issuer mismatch and discard the list as inapplicable. For external
CAs revocation checking works through OCSP - [07-ocsp.md](07-ocsp.md).

The Root CA CRL is built from `ca_certs` with `type_ca = 'Sub' AND cert_status = 2`.

## Revocation entries

`createRevokedEntry` builds a `pkix.RevokedCertificate`:

- **Serial number** - converted from the hex string in the database into a `big.Int`.
- **Revocation time** - parsed from `data_revoke` (RFC 3339). If parsing fails, the
  current time is used and a warning goes into the log.
- **Reason** - the `reasonCode` extension (OID 2.5.29.21), an ASN.1 ENUMERATED. The
  value `unspecified (0)` is omitted, as recommended by RFC 5280 §5.3.1.

The mapping from text to code is `crl.GetRevocationReason` (RFC 5280 §5.3.1):

| Text in the database | Code |
|---|---|
| `unspecified` / empty | 0 |
| `keyCompromise` | 1 |
| `cACompromise` | 2 |
| `affiliationChanged` | 3 |
| `superseded` | 4 |
| `cessationOfOperation` | 5 |
| `certificateHold` | 6 |
| `removeFromCRL` | 8 |
| `privilegeWithdrawn` | 9 |
| `aACompromise` | 10 |

The function lowercases its input, which is why all `case` labels are written in
lowercase. The same function is used by OCSP - revocation reason codes are shared
between both mechanisms.

## CRL number and validity window

Metadata lives in `sub_ca_crl_info` and `root_ca_crl_info`: version, signature
algorithm, issuer, `last_update`, `next_update`, `crl_number`, URL. `crl_number` is
incremented on every generation - RFC 5280 §5.2.3 requires monotonic growth, otherwise a
client may consider the new list stale and keep its cached copy.

`nextUpdate` is computed as `now + CAcrl.updateInterval`. If the configuration key is
read incorrectly the interval becomes zero and `nextUpdate` equals `thisUpdate` -
clients will treat the list as expired the moment it is issued. The
`tests/crl/test_crl.sh` script checks specifically for this.

## When the CRL is regenerated

| Event | Where it is triggered |
|---|---|
| Application startup | `StartCombinedCRLGeneration` |
| On schedule | the `CAcrl.updateInterval` ticker |
| Certificate revocation | `RevokeCert`, `RevokeUserCert`, `RevokeESTCert` |
| Revocation rollback | `RollbackCert`, `RollbackUserCert`, `RollbackESTCert` |
| Sub CA reissuance | `RevokeCACertWithData` |
| Manually | `POST /api/v1/crl/bundleca/generate` (requires an API key with the `write` scope) |

Regenerating after every revocation means clients do not have to wait for the daily
tick - the new list is available immediately. An important implementation detail:
`CombinedCRL(db)` is called **after** `tx.Commit()`. Internally the generator opens its
own SQLite connections which cannot see an uncommitted transaction, so without the
commit the list would carry the previous certificate status.

## Storage and delivery

`CombinedCRL` writes three rows into the `crl` table (`Sub`, `Root`, `Bundle`) in PEM
format. The `/pem` endpoints return the content as is, `/der` decode the PEM back into
DER. Headers: `application/x-pem-file` and `application/pkix-crl` respectively.

## How to verify

```bash
./tests/crl/test_crl.sh              # latest EST certificate
./tests/crl/test_crl.sh <SERIAL>     # a specific one
```

The script checks the CDP in the certificate, parsing of both CRLs, the match between
the certificate AKI and the CRL signer AKI, presence of the serial number in the list,
the validity window and the full chain through `openssl verify -crl_check_all`.

Manually:

```bash
curl -sS http://tlss.lv.local:8080/api/v1/crl/subca/pem -o subca.crl
openssl crl -in subca.crl -text -noout | head -20
```
