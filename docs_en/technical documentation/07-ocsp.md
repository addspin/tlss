# 07. OCSP - online status checking

Implemented in the [`ocsp`](../../ocsp/ocspResponder.go) package, with the HTTP layer in
[`OCSPController.go`](../../controllers/ocspControllers/OCSPController.go). Library:
`golang.org/x/crypto/ocsp`.

## Standards

| RFC | What is taken from it |
|---|---|
| **RFC 6960** | Request and response format, issuer resolution by hashes, statuses, `responderID` |
| **RFC 5019** | Lightweight profile: mandatory `nextUpdate`, `unauthorized` for an unknown serial, HTTP caching |
| **RFC 5280** | The AIA extension (`id-ad-ocsp`), revocation reason codes |

## Decisions taken

| Question | Choice | Rationale |
|---|---|---|
| What signs the responses | the CA key itself (`responderID = byName`) | CA keys are already used online for issuing certificates and CRLs; a delegated responder certificate would add entities without any security gain |
| Nonce (RFC 8954) | not supported | RFC 5019 profile: responses are cacheable. Clients need the `-no_nonce` flag |
| Unknown serial | `unauthorized (6)` | RFC 5019 §2.2.3 - prevents using the responder as an oracle for serial enumeration |

## Endpoints

They live on the public HTTP listener (`app.crl_port`, 8080 by default) - the same one
that serves CRLs:

```
POST /ocsp           body - DER-encoded OCSPRequest
GET  /ocsp/{base64}  base64(DER), URL-encoded, in the path
```

Both variants are described in RFC 6960 Appendix A.1. GET exists for proxy caching;
RFC 5019 §5 tells clients to use it for requests shorter than 255 bytes.

Parsing the GET form requires care: the base64 alphabet contains `+`, `/` and `=`, which
the client must encode as `%2B`, `%2F`, `%3D`. The controller takes the **original**
path (`c.RequestCtx().URI().PathOriginal()`) so the `%XX` sequences are not lost, and
only then decodes it. If the client did not encode anything, an attempt is made to parse
the string as is.

## How issuer resolution works

The request carries no CA name, only hashes (RFC 6960 §4.1.1):

- `IssuerNameHash` - hash of the DER representation of the issuer Subject
- `IssuerKeyHash` - hash of the `subjectPublicKey` BIT STRING contents (without the tag
  and unused bits)

The hash algorithm is chosen by the client (usually SHA-1). The responder:

1. `loadCACandidates` gathers every possible signer: the Core Sub CA, the Core Root CA
   and each active external CA that has a private key.
2. `matchIssuer` computes both hashes for every candidate **with the same algorithm** as
   in the request and looks for a match.
3. The matched CA determines where the serial number is searched.

This is exactly why the AIA of all certificates carries a **single** URL, unlike CRL
where the addresses differ. One endpoint serves the whole hierarchy.

## Areas of responsibility

| `scopeKind` | Who signs | Where the serial is searched |
|---|---|---|
| `scopeCoreEndEntity` | Core Sub CA | `certs`, `user_certs`, `est_certs` with `signing_ca_id = 0` |
| `scopeCoreSubCA` | Core Root CA | `ca_certs` with `type_ca = 'Sub'` |
| `scopeExternal` | external CA | the same three tables with `signing_ca_id = entity_ca.id` |

The serial number is converted to the database format:
`strings.ToUpper(req.SerialNumber.Text(16))`.

## Building the response

```go
template := xocsp.Response{
    SerialNumber: req.SerialNumber,
    ThisUpdate:   now,
    NextUpdate:   now.Add(validity),  // RFC 5019 §2.2.4 - mandatory
    IssuerHash:   req.HashAlgorithm,  // must match the request
}
```

Status mapping:

| `cert_status` in the database | OCSP status | Explanation |
|---|---|---|
| `0` valid | `good` | |
| `1` expired | `good` | RFC 6960 §2.2: OCSP reports **revocation only**. Validity is checked by the client itself against `NotAfter` |
| `2` revoked | `revoked` plus time and reason | The reason comes from `crl.GetRevocationReason`, shared with CRL |

Error situations are returned as valid unsigned `OCSPResponse` messages with the
corresponding `responseStatus`, not as HTTP errors:

| Situation | Response |
|---|---|
| Request could not be parsed | `malformedRequest (1)` |
| No CA available / signing failure | `internalError (2)` |
| Unknown issuer or serial | `unauthorized (6)` |

## Caching (RFC 5019 §6)

Signed responses carry:

```
Cache-Control: max-age=<until nextUpdate>, public, no-transform, must-revalidate
Last-Modified: <thisUpdate>
Expires: <nextUpdate>
ETag: "<SHA-1 hex of the response body>"
```

SHA-1 here is not a cryptographic function but a cache identifier; the format is
prescribed directly by RFC 5019. Error responses are marked `no-cache, no-store` -
caching `unauthorized` is not acceptable.

## How to verify

```bash
./tests/ocsp/test_ocsp.sh                 # latest server certificate
./tests/ocsp/test_ocsp.sh <SERIAL>        # a specific one
./tests/revocation/test_revocation.sh     # database vs CRL vs OCSP consistency
```

Manually:

```bash
sqlite3 db/database.db "SELECT public_key FROM ca_certs WHERE type_ca='Sub' AND cert_status=0;" > sub_ca.pem
sqlite3 db/database.db "SELECT public_key FROM certs ORDER BY id DESC LIMIT 1;" > cert.pem

openssl ocsp -issuer sub_ca.pem -cert cert.pem \
  -url http://tlss.lv.local:8080/ocsp -no_nonce -CAfile sub_ca.pem -resp_text
```

The expected output contains `Cert Status: good` (or `revoked`) and
`Response verify OK`.
