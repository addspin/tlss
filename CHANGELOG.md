## [v1.5.1] - 24.08.26

**IMPORTANT:**
- Building now requires **Go 1.27.0 or later** (`go` directive in `go.mod` raised from
  `1.25.0`). With `GOTOOLCHAIN=auto` the correct toolchain is downloaded automatically;
  older toolchains will refuse to build the module directly.

Security-only release: no functional changes, no configuration changes, no database
migrations.

**Security:**

Two GitHub Dependabot alerts in `github.com/gofiber/fiber/v3` (fixed in v3.3.0):
- `X-Real-IP` spoofing in `BalancerForward` — the proxy helper used `Header.Add()`
  instead of `Header.Set()`, appending the real client IP as a second header value
  instead of replacing an attacker-supplied one. Upstream servers reading the first
  value would trust the spoofed IP for rate limiting, ACLs and audit logs
- Username enumeration via a timing oracle in the `BasicAuth` default authorizer —
  short-circuit evaluation skipped the bcrypt comparison for unknown users, producing
  a ~1,000,000:1 timing difference between existing and non-existing usernames

Neither was reachable from TLSS: `middleware/proxy` and `middleware/basicauth` are not
imported by this project. Updated regardless.

Twenty-two Go standard library vulnerabilities reported by `govulncheck` against
Go 1.25.5, all closed by the toolchain upgrade. Most relevant to a CA are the ASN.1
and X.509 issues, which are reachable from client-supplied CSRs and certificates, and
the `html/template` escaper bypasses, which are reachable from every rendered page:
- `encoding/asn1` — GO-2026-5972 (missing recursion depth limit; a malicious CSR
  submitted to the EST endpoints could exhaust the stack)
- `crypto/x509` — GO-2026-5037, GO-2026-4947, GO-2026-4946 (inefficient hostname
  parsing, unexpected work during chain building, inefficient policy validation)
- `html/template` — GO-2026-6091, GO-2026-4982, GO-2026-4980, GO-2026-4865,
  GO-2026-4603 (XSS through escaper and JavaScript context tracking bypasses)
- `crypto/tls` — GO-2026-6090, GO-2026-5856, GO-2026-4870, GO-2026-4340, GO-2026-4337
  (post-handshake message flooding, Encrypted Client Hello privacy leak, KeyUpdate
  denial of service, wrong encryption level, unexpected session resumption)
- `net/url` — GO-2026-6218, GO-2026-4601, GO-2026-4341 (quadratic complexity in
  `resolvePath`, IPv6 host literal parsing, memory exhaustion in query parsing)
- `net/http` — GO-2026-5026, GO-2026-4918 (Punycode label handling, infinite loop on
  a bad HTTP/2 `SETTINGS_MAX_FRAME_SIZE`)
- `net/textproto` — GO-2026-5039 (unescaped input in errors)
- `net` — GO-2026-4971 (panic on a NUL byte, Windows only)
- `os` — GO-2026-4602 (`FileInfo` escaping from a `Root`)

One vulnerability in a dependency:
- `golang.org/x/text` — GO-2026-5970, infinite loop on invalid input, reachable through
  Unicode normalization during ZIP bundle creation. Fixed in v0.39.0

**Update:**
- Go toolchain 1.25.5 -> 1.27.0
- `github.com/gofiber/fiber/v3` v3.2.0 -> v3.5.0
- `github.com/spf13/viper` v1.20.0-alpha.6 -> v1.21.0 (off a pre-release version)
- `golang.org/x/crypto` v0.52.0 -> v0.54.0
- Indirect dependencies: `golang.org/x/text` v0.37.0 -> v0.40.0, `golang.org/x/net`
  v0.55.0 -> v0.57.0, `golang.org/x/sys` v0.45.0 -> v0.47.0, `github.com/valyala/fasthttp`
  v1.70.0 -> v1.73.0, `github.com/klauspost/compress` v1.18.5 -> v1.19.2,
  `github.com/gofiber/schema` v1.7.1 -> v1.8.3, `github.com/gofiber/utils/v2` v2.0.4 ->
  v2.4.1, plus the viper dependency tree
- CI (`.github/workflows/go.yml`): the Linux amd64 build container moved from
  `golang:1.25-alpine` to `golang:1.27-alpine`; the Linux arm64 and macOS jobs now use
  `go-version-file: 'go.mod'` instead of a hardcoded `go-version: '1.25.3'`, so the
  toolchain version is defined in one place and cannot drift from the module

## [v1.5.0] - 18.08.26

**IMPORTANT:**
- OCSP responder added. Add the `CAocsp` section to `config.yaml` (or recreate the config):
```yaml
CAocsp:
  url: http://tlss.lv.local:8080/ocsp # AIA (id-ad-ocsp) for all issued certs
  unit: hours # minutes, seconds, hours
  responseValidity: 24 # hours, response validity (nextUpdate)
```
- The AIA extension is written only into **newly issued** certificates. Existing ones
  have no responder address, so clients will not find it on their own — reissue the
  certificates if you need OCSP checks for them.

**Add:**
- OCSP responder according to RFC 6960 with the lightweight profile of RFC 5019:
  - `POST /ocsp` - DER-encoded OCSPRequest in the body
  - `GET /ocsp/{base64}` — base64(DER) in the path (RFC 6960 Appendix A.1)
  - Responses are signed by the CA that issued the certificate (`responderID = byName`)
  - The issuer is resolved from `IssuerNameHash`/`IssuerKeyHash` of the request, so a
    single endpoint serves the whole hierarchy: Core Sub CA, Core Root CA and external CAs
  - `unauthorized (6)` is returned for an unknown serial (RFC 5019) so the
    responder cannot be used as an oracle
  - HTTP caching headers according to RFC 5019
  - Runs on the public CRL listener (`app.crl_port`, HTTP by default)
- AIA extension (`id-ad-ocsp`) in all issued certificates: server, client, EST and Sub CA
- Documentation in `docs_en/`:
  - `technical documentation/` - architecture, configuration, database, crypto, CRL,
    OCSP, EST, API, checkers, UI, testing and a summary of known issues
  - `user documentation/` — initialization and production setup
- Test scripts:
  - `tests/ocsp/test_ocsp.sh` - AIA, POST and GET requests, caching, `unauthorized`,
    Sub CA status via Root CA
  - `tests/revocation/test_revocation.sh` - end-to-end consistency between the database,
    CRL and OCSP; returns a non-zero exit code on mismatch

**Fix:**
- `keyCompromise` was never matched in `GetRevocationReason`: the input is lowercased,
  but the case label was written in camelCase. Revocations with this reason were
  published in the CRL as `unspecified`
- CRL metadata used the non-existent configuration key `CAcrl.crlURL`, so an empty
  string was written to the `crl_url` column of `sub_ca_crl_info` and `root_ca_crl_info`
- Certificates issued by external CAs were included in the Sub CA CRL. That CRL is
  signed by our Sub CA and is not applicable to them - a client would reject it.
  Revocation for such certificates is served via OCSP
- Certificates issued through the EST protocol had no CDP and no AIA at all
- `simplereenroll` did not verify that Subject and SubjectAltName match the certificate
  being renewed (RFC 7030). The owner of any valid certificate could issue one
  for an arbitrary name
- The EST trusted CA pool was built once at startup: after reissuing the Sub CA, clients
  with new certificates could not pass mTLS until a restart. The pool is now rebuilt on
  handshake with a short cache and is reset immediately when the Sub CA is reissued
- Monitor poll intervals for the recreate and validity checkers were taken from the
  checker sections instead of `monitor.*`, so four configuration keys were ignored and
  the monitor woke up less often than configured

**Update:**
- `GetRevocationReason` is now exported from the `crl` package and shared with OCSP -
  revocation reason codes are common to both mechanisms

## [v1.4.1] - 09.06.26

**IMPORTANT:**
- Added splitting APP UI, EST, CRL endpoints
- Default CRl use http protocol and start on 8080 port, please update config.yaml or recreate config:
```yaml
app:
  crl_port: 8080 
  crl_protocol: http 

CAcrl:
  subCACrlURL: http://tlss.lv.local:8080/api/v1/crl/subca/pem 
  rootCACrlURL: http://tlss.lv.local:8080/api/v1/crl/rootca/pem 
```

## [v1.4.0] - 19.05.26
Details below:

**Add:** 
- Added support for the EST protocol (RFC 7030)
According to RFC 7030, the following URIs are supported:

Mandatory:
- Distribution of CA - /.well-known/est/cacerts/
- Enrollment of Clients - /.well-known/est/simpleenroll
- Re-enrollment of Clients - /.well-known/est/simplereenroll
Optional:
- CSR Attributes - /.well-known/est/csrattrs (due to differences in the structure of the original RFC 7030 and the addition in RFC 9908, the `estCSRAttrs` parameter has been added to the configuration)
Required for proper application operation:
```yaml
estCSRAttrs:
  rfc9908: true # true - use RFC 9908, false - use RFC 7030
```

**Update:** 
- Added configuration specifying endpoints for root CA / sub CA to retrieve CRLs (according to RFC 5280, each certificate specifies a CDP (**CRL Distribution Point**) pointing to the CRL of its issuer). The bundle is also saved.

**IMPORTANT:**

Because I forgot to add CDP links for root CA / sub CA to the configuration and instead left a link to the bundle, your current signing certificate will lack them. As a result, all issued certificates will produce an error during full verification, for example via openssl **`openssl verify -crl_check_all`**. Unfortunately, the only solution is to reissue the sub CA after changing the configuration.
The current valid configuration contains the following parameters for CDP:
```yaml
CAcrl:
  subCACrlURL: https://tlss.lv.local:43000/api/v1/crl/subca/pem # CRL signed by Sub CA, for end-entity certs
  rootCACrlURL: https://tlss.lv.local:43000/api/v1/crl/rootca/pem # CRL signed by Root CA, for Sub CA certs
  unit: hours # minutes, seconds, hours
  updateInterval: 24 # interval of CRL update
```

**Fix:** 
- When creating a new Sub CA, the cache was not cleared, leading to the recreation of certificates signed by a revoked Sub CA
- CRL was not updated after recreating a Sub CA (required waiting for the next update)
- Time update (next update) in CRL
- Fixed certificate serial number display in Certificate Info, now consistent with the database and openssl display

**Update:** 
- Certificate revoke/rollback now updates the CRL immediately without waiting for the global update

**Add:** 
- Added information to Certificate Info for chain debugging:
  - **Subject Key Identifier** - for CA certificates, this is the identifier of their own key
  - **Authority Key Identifier** - for end-entity certificates and Sub CA, points to the issuer's key (parent's `SKI`)