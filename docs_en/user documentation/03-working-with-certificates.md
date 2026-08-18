# 03. Working with certificates

An overview of the interface sections and the differences between them.

## Without authorization

Two sections are available to everyone:

| Section | What it gives |
|---|---|
| **Home -> Overview** | Statistics and general information about the installation |
| **Tools -> Certificate Info** | Inspection of an uploaded certificate - through the file browser or drag and drop |

Certificate Info shows the Subject, issuer, serial number, validity dates, SAN, key
usage, revocation checking endpoints, as well as the Subject Key Identifier and the
Authority Key Identifier - the last two are handy when troubleshooting chains.

## Servers certs

The section for certificates that services use to accept connections.

- **Add ssh key** - your own SSH keys for connecting to the servers where certificates
  will be copied
- **Add servers** - the servers that delivery is possible to
- Certificates are issued with **TLS Web Server Authentication** and **TLS Web Client
  Authentication** - suitable both for accepting connections and for mutual
  authentication between cluster nodes
- The domain is added to SAN automatically, even if the field is left empty
- With the **Save to server** switch enabled, the certificate is copied to the selected
  server over SSH. For a server in the `offline` state, issuance with this option is
  rejected

## Clients certs

The section for certificates that clients use to connect to services.

- **Add entities** - the entities certificates are attached to
- **Add OIDs** - additional custom fields in the certificate
- Certificates are issued with **TLS Web Client Authentication**

## EST

Automated certificate issuance for devices over the RFC 7030 protocol.

| Subsection | Purpose |
|---|---|
| **Add EST users** | Accounts for the initial issuance: login, password, issuance limit, account lifetime |
| **Add EST certs** | Manual issuance without involving the protocol |
| **Revoke EST certs** | Revocation, rollback and deletion |

A device gets its first certificate using a login and password, and renews it by
presenting the issued certificate - the password is no longer needed for that.

The issuance counter limits how many certificates a single account can produce: once it
is exhausted, the account moves to the `disabled` state.

## The Recreate switch

Available when issuing server and client certificates. When enabled, an expired
certificate is reissued automatically - locally and, if Save on server was used,
copied to the server again.

It only applies to expired certificates. A valid certificate cannot be renewed this way.

## Revocation and rollback

Revocation requires a reason - it ends up in the CRL and in OCSP responses. The list is
regenerated right away, there is no need to wait for the scheduled update.

Rollback puts the certificate back in service: the entry disappears from the CRL and
OCSP answers `good` again.

Revoking one certificate does not affect the others: each exists independently.
Issuing again for the same object creates a new certificate rather than replacing the
existing one.

## Reissuing the CA

Revoking the Root or Sub CA triggers a chain reaction:

1. Every certificate signed by that CA is revoked
2. Previously revoked and expired ones are deleted
3. A new CA is created
4. All valid certificates are issued again under the new CA
5. Those stored on servers are copied again
6. The CRL is regenerated

The operation affects the whole installation at once, so it is worth planning: until
the reissuance completes, clients holding the old certificates will fail chain
validation.

Certificates signed by external CAs are not part of this process - they do not depend
on your hierarchy.

## External CAs

The **CA -> External CA** section lets you upload someone else's hierarchy
(certificates and keys) and sign certificates with it. A **Signing CA** field then
appears during issuance.

One specific: revocation checking for such certificates works through OCSP. They are
not included in the CRL - that list is signed by your Sub CA and does not apply to a
foreign hierarchy.

## Download formats

Three formats are available for every certificate:

| Format | Contents |
|---|---|
| **zip** | Certificate, private key and the CA chain |
| **pkcs12** | A `.p12` container, modern encryption |
| **pkcs12-legacy** | A `.p12` container for macOS and older software |

The container password is the one specified at issuance.
