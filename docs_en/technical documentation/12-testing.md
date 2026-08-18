# 12. Testing

The checks are implemented as bash scripts under `tests/`. There are no Go tests
(`*_test.go`) in the project - everything being verified needs a live database, running
listeners and real cryptographic operations, so the tests run against a running
application.

| Script | What it verifies |
|---|---|
| `tests/crl/test_crl.sh` | CRL: CDP, signer, contents, validity window, chain |
| `tests/ocsp/test_ocsp.sh` | OCSP: AIA, POST and GET, caching, `unauthorized`, Sub CA status |
| `tests/est/test_est.sh` | EST: the full enroll -> reenroll cycle, `max_uses` blocking |
| `tests/revocation/test_revocation.sh` | End-to-end reconciliation: database vs CRL vs OCSP |

## Common properties

All scripts locate the project root themselves by walking up the tree until they find
`go.mod`, so they can be launched from anywhere:

```bash
./tests/ocsp/test_ocsp.sh
cd tests/ocsp && ./test_ocsp.sh
```

Settings are overridden through environment variables: `DB`, `BASE_URL`, `CRL_URL`,
`OCSP_URL`, `EST_URL`. Temporary files are created with `mktemp -d` and removed by a
`trap`.

**A running application is required** - the scripts talk to live endpoints.

## test_crl.sh

```bash
./tests/crl/test_crl.sh [<SERIAL>]
```

Eight steps: it pulls a certificate from the database, prints the CDP, Issuer and AKI,
downloads both CRLs, shows their contents and whether the serial is present, compares
the certificate AKI with the CRL signer AKI, checks the CDP inside the Sub CA itself and
runs `openssl verify -crl_check_all`.

A dedicated `check_crl_validity_window` function verifies that `nextUpdate` is shifted
relative to `thisUpdate` and matches `CAcrl.updateInterval`. This is a regression test:
when a non-existent configuration key is read the interval becomes zero and the CRL is
expired the moment it is issued.

Situations it diagnoses:

| Symptom | Cause |
|---|---|
| `AKI cert == AKI CRL signer: NO` | The certificate was issued by a previous Sub CA that has since been replaced |
| `unable to get certificate CRL` | The Sub CA has no CDP - it was issued before that was introduced |
| `nextUpdate == thisUpdate` | The interval was not read from the configuration |

## test_ocsp.sh

```bash
./tests/ocsp/test_ocsp.sh [<SERIAL>]
```

Nine steps: AIA in the certificate, a POST request with response signature validation, a
GET request with base64 in the path, comparison of the POST and GET statuses, caching
headers, a Sub CA status request through the Root CA (the `scopeCoreSubCA` branch), and
a check that an unknown serial yields `unauthorized`.

The responder URL is taken from the certificate's own AIA - this verifies that a client
would indeed be able to find the responder on its own.

## test_est.sh

```bash
./tests/est/test_est.sh <username> <password> [<cn>]
```

Requires an EST user created in advance (the **Add EST users** section). Nine steps:
`cacerts`, CSR generation, `simpleenroll`, chain validation, `simplereenroll` over mTLS,
verification that the serial number changed, the statuses in `est_certs` (old one `2`,
new one `0`), the account state and, when `max_uses` is exhausted, that a repeated
enroll returns 401.

The full cycle is exercised with a user having `MaxUses = 1`. The script uses the same
CN for both CSRs, so the identity check passes as expected.

## test_revocation.sh

```bash
./tests/revocation/test_revocation.sh [<SERIAL>]
```

The strictest script: it reconciles three sources and returns a non-zero exit code on a
mismatch, which makes it suitable for CI.

The expectation matrix:

| `cert_status` | `signing_ca_id` | In the CRL | In OCSP |
|---|---|---|---|
| `2` revoked | `0` - Core Sub CA | yes | `revoked` |
| `2` revoked | `-1` - Sub CA under the Root | yes | `revoked` |
| `2` revoked | `>0` - external CA | **no** | `revoked` |
| `0` / `1` | any | no | `good` |

The third row captures a deliberate decision: certificates of external CAs are excluded
from our CRL (it is signed by a different key and does not apply to them) but are served
over OCSP.

The revocation reason and the **point in time** are reconciled as well - the timestamps
from the database, the CRL and OCSP are converted to unix time and compared numerically.
That removes false mismatches caused by representation: the database stores
`2026-08-14T09:45:12+04:00` while the protocols show `Aug 14 05:45:12 2026 GMT`, which is
the same instant.

The script also accounts for openssl padding the serial number with a leading zero to an
even length, and matches both spellings.

## A typical verification scenario

```bash
# 1. State before revocation
./tests/revocation/test_revocation.sh <SERIAL>     # expected: good

# 2. Revoke the certificate through the UI

# 3. State afterwards - the CRL is regenerated immediately, no need to wait for a tick
./tests/revocation/test_revocation.sh <SERIAL>     # expected: revoked

# 4. Roll the revocation back through the UI and verify the return
./tests/revocation/test_revocation.sh <SERIAL>     # good again
```

## Manual checks

```bash
# Configuration integrity (see 02-configuration.md)
grep -rhoE 'viper\.Get[A-Za-z]+\("[^"]+"\)' --include="*.go" . \
  | grep -oE '"[^"]+"' | tr -d '"' | sort -u

# Build and static analysis
go build ./... && go vet ./... && gofmt -l .

# Syntax of the test scripts
for f in tests/*/*.sh; do bash -n "$f" && echo "OK: $f"; done
```
