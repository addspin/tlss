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