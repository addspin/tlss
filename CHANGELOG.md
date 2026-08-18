## [v1.5.0] - 18.08.26

**IMPORTANT:**
- OCSP responder added. Add the `CAocsp` section to `config.yaml` (or recreate the config):
```yaml
CAocsp:
  url: http://tlss.lv.local:8080/ocsp # AIA (id-ad-ocsp) for all issued certs
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