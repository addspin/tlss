# 08. EST - Enrollment over Secure Transport

An implementation of **RFC 7030**: automated certificate issuance and renewal for
devices. Controllers live in [`estControllers`](../../controllers/estControllers/), CSR
signing in [`crypts/estSign.go`](../../crypts/estSign.go), authentication in
`middleware/estBasicAuth.go` and `middleware/estCertAuth.go`.

## A separate port and mTLS

The EST server runs on `app.est_port` (43001 by default) and **always** uses TLS, as
required by RFC 7030 §3.3. The TLS configuration:

```go
tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
tlsConfig.ClientCAs  = clientCAPool   // crypts.BuildESTClientCAPool
```

`VerifyClientCertIfGiven` means a client certificate is optional, but if presented, its
chain is validated against the pool of our CAs. This mode lets one listener serve both
`simpleenroll` (Basic Auth, no certificate yet) and `simplereenroll` (mTLS).

The reason for a dedicated port: the client certificate is requested during the TLS
handshake, when the server does not yet know the URL. Enabling mTLS "for one route only"
is impossible, and enabling it on the UI port is undesirable - browsers would start
showing a certificate selection dialog.

## Endpoints

| Method and path | Authentication | RFC |
|---|---|---|
| `GET /.well-known/est/cacerts` | none | 7030 §4.1 |
| `GET /.well-known/est/csrattrs` | none | 7030 §4.5 |
| `POST /.well-known/est/simpleenroll` | HTTP Basic | 7030 §4.2 |
| `POST /.well-known/est/simplereenroll` | mTLS | 7030 §4.2.2 |

### cacerts

Returns the CA chain as a "degenerate" PKCS#7 (certificates only, no signature):
`pkcs7.NewSignedData([]byte{})` plus `AddCertificate` for each active CA. The body is
base64, with the `application/pkcs7-mime; smime-type=certs-only` and
`Content-Transfer-Encoding: base64` headers.

### csrattrs

Tells the client which attributes the server expects in a CSR. Two formats are
supported, switched by the `estCSRAttrs.rfc9908` flag:

| Value | Structure |
|---|---|
| `false` - RFC 7030 §4.5.2 | `SEQUENCE { OID commonName, Attribute { id-ExtensionReq, SET { OID subjectAltName } } }` |
| `true` - RFC 9908 | `id-aa-extensionReqTemplate` is used instead of `id-ExtensionReq`, with a nested `Extensions SEQUENCE` |

The flag exists because clients of different generations understand different variants.
In practice the server only uses `Subject.CommonName` and SAN from the CSR - the
remaining extensions (KeyUsage, ExtKeyUsage, BasicConstraints) are set by the server and
ignored from the CSR.

### simpleenroll

1. `ESTBasicAuth` verifies the login and password against the `est_users` table (bcrypt),
   and also that the account is active and the `max_uses` counter is not exhausted.
2. The request body is decoded: base64 first, then PEM, then raw DER.
3. `crypts.SignCSR` parses the PKCS#10, **verifies the CSR signature** and signs a
   certificate with the selected CA (`est_users.signing_ca_id`).
4. The certificate is stored in `est_certs` - this is what makes a later reenroll possible.
5. `max_uses` is decremented; when it reaches zero the user moves to the `disabled` state.
6. The response is a PKCS#7 carrying one certificate
   (`pkcs7.DegenerateCertificate`), base64 encoded.

The validity period comes from `est.cert_ttl_enrollment`. There is no standard way to
request a specific lifetime in a PKCS#10, so this is a server-side decision.

### simplereenroll

1. `ESTCertAuth` takes the client certificate from the TLS state
   (`c.RequestCtx().TLSConnectionState().PeerCertificates[0]`) - the chain has already
   been validated at the TLS level.
2. The serial number is looked up in `est_certs`. This rules out certificates issued
   through the UI outside EST, even if they were signed by the same CA.
3. The certificate is checked for not being revoked or expired.
4. **The Subject and SAN** of the new CSR are compared against the presented certificate
   (RFC 7030 §4.2.2). A mismatch returns `403`.
5. The new CSR is signed with the same `signing_ca_id` and `ttl` as the presented
   certificate.
6. The new record is stored and the **old certificate is revoked** with the reason
   `superseded`.

An EST user is not needed at this step: per the RFC a valid certificate is enough. The
`est_user_id` field is carried over into the new record only as a historical trace.

### Identity check

`checkIdentityUnchanged` compares:

| Field | Comparison method |
|---|---|
| Subject | byte-for-byte over DER (`RawSubject`) |
| DNS names, email, IP, URI | as sets - the order of values does not matter |

Without this check the owner of any valid EST certificate could issue one for an
arbitrary name: authentication only proves possession of a key, while the CSR contents
were previously unconstrained.

The `ChangeSubjectName` attribute (RFC 6402), which a client could use to explicitly
request a name change, is not supported - any divergence is rejected.

## EST users

The `est_users` table holds the accounts used for the initial issuance:

| Field | Meaning |
|---|---|
| `password_hash` | bcrypt |
| `max_uses` | how many more certificates may be issued |
| `ttl`, `user_expire_time` | lifetime of the **account**, not of the certificate |
| `user_status` | `0` active, `1` expired, `3` disabled (`max_uses` exhausted) |
| `signing_ca_id` | which CA signs certificates issued to this user |

Two independent blocking mechanisms:

- `max_uses` reaches zero -> `user_status = 3` (set in `SimpleEnroll`)
- `user_expire_time` passes -> `user_status = 1` (set by the `CheckValidCerts` checker)

In both cases `ESTBasicAuth` returns 401.

A side effect: the CA for a device is chosen by choosing the account - the client only
supplies a login and password, while the signing CA is determined by the `est_users`
record.

## UI

Three menu sections:

| Section | Route | Purpose |
|---|---|---|
| Add EST users | `/est_users` | Creating and deleting accounts |
| Add EST certs | `/add_est_certs` | Manual issuance without the protocol |
| Revoke EST certs | `/revoke_est_certs` | Revocation, rollback, deletion |

Manual issuance through the UI writes into the same `est_certs` table, so such a
certificate can later be renewed through `simplereenroll`.

## How to verify

```bash
./tests/est/test_est.sh <username> <password>
```

The script walks through the full cycle: `cacerts` -> CSR generation -> `simpleenroll`
-> chain validation -> `simplereenroll` over mTLS -> status reconciliation in the
database -> the `max_uses` blocking check.

Manually:

```bash
# CA chain
curl -sk https://tlss.lv.local:43001/.well-known/est/cacerts \
  | base64 -d | openssl pkcs7 -inform DER -print_certs -noout -text

# CSR attributes
curl -sk https://tlss.lv.local:43001/.well-known/est/csrattrs \
  | base64 -d | openssl asn1parse -inform DER

# Issuance
openssl req -new -newkey rsa:2048 -nodes -keyout client.key -out client.csr -subj "/CN=device-01"
openssl req -in client.csr -outform DER | base64 | \
  curl -sk -u "user:pass" -X POST -H "Content-Type: application/pkcs10" \
    --data-binary @- https://tlss.lv.local:43001/.well-known/est/simpleenroll \
  | base64 -d | openssl pkcs7 -inform DER -print_certs -out client.crt

# Renewal over mTLS
openssl req -new -newkey rsa:2048 -nodes -keyout client2.key -out client2.csr -subj "/CN=device-01"
openssl req -in client2.csr -outform DER | base64 | \
  curl -sk --cert client.crt --key client.key -X POST -H "Content-Type: application/pkcs10" \
    --data-binary @- https://tlss.lv.local:43001/.well-known/est/simplereenroll
```
