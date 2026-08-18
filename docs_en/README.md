# TLSS - documentation

The documentation is split in two parts: one answers "how to use it", the other one
"how it works inside".

## User documentation

[user documentation/](user%20documentation/contents.md) - startup, configuration and
day-to-day work through the web interface.

| Document | Contents |
|---|---|
| [First run and initialization](user%20documentation/01-getting-started.md) | What the application asks on startup, creating the CA, verifying that everything works |
| [Preparing for production](user%20documentation/02-production-setup.md) | Which parameters to change before going live and why |
| [Working with certificates](user%20documentation/03-working-with-certificates.md) | Interface sections, certificate types, revocation and reissuance |

## Technical documentation

[technical documentation/](technical%20documentation/contents.md) - component design,
database schema, protocol implementation.

| Topic | Document |
|---|---|
| Architecture, listeners, startup order | [01-architecture.md](technical%20documentation/01-architecture.md) |
| Breakdown of `config.yaml` | [02-configuration.md](technical%20documentation/02-configuration.md) |
| Tables and relations | [03-database.md](technical%20documentation/03-database.md) |
| Cryptography, CA hierarchy | [04-crypto.md](technical%20documentation/04-crypto.md) |
| Certificate lifecycle | [05-certificates.md](technical%20documentation/05-certificates.md) |
| CRL - RFC 5280 | [06-crl.md](technical%20documentation/06-crl.md) |
| OCSP - RFC 6960, RFC 5019 | [07-ocsp.md](technical%20documentation/07-ocsp.md) |
| EST - RFC 7030 | [08-est.md](technical%20documentation/08-est.md) |
| REST API and authentication | [09-api.md](technical%20documentation/09-api.md) |
| Background checkers and monitor | [10-checkers.md](technical%20documentation/10-checkers.md) |
| Web interface and templates | [11-web-ui.md](technical%20documentation/11-web-ui.md) |
| Test scripts | [12-testing.md](technical%20documentation/12-testing.md) |

## Quick answers

| Question | Where to look |
|---|---|
| How do I start it the first time | [First run](user%20documentation/01-getting-started.md) |
| What to change before production | [Production setup](user%20documentation/02-production-setup.md) |
| Why can't I issue certificates | Root and Sub CA are not created yet - [First run](user%20documentation/01-getting-started.md) |
| How do I verify revocation works | [Testing](technical%20documentation/12-testing.md) |
| Which RFCs are implemented | [Technical documentation index](technical%20documentation/contents.md) |
