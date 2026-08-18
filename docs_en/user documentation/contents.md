# TLSS - user documentation

How to start TLSS, prepare it for production and work with certificates through the
web interface.

## Sections

| Document | Contents |
|---|---|
| [01-getting-started.md](01-getting-started.md) | First run, what the application asks, creating the CA, verifying that it works |
| [02-production-setup.md](02-production-setup.md) | What to change in `config.yaml` before going live and why |
| [03-working-with-certificates.md](03-working-with-certificates.md) | Interface sections, differences between certificate types, revocation and reissuance |

## Where to start

**Fresh installation** - in order: [01](01-getting-started.md) -> [02](02-production-setup.md).

**Preparing for production** - go straight to [02-production-setup.md](02-production-setup.md).
Pay attention to the CRL and OCSP addresses: they are embedded into the certificates
themselves, so changing them after issuance is too late.

**Getting familiar with the interface** - [03-working-with-certificates.md](03-working-with-certificates.md).

## What you need to know upfront

**The administrator password cannot be recovered.** It encrypts the master key, which
in turn encrypts every private key in the database. There is no backup copy - losing
the password means losing all keys.

**No CA means no certificates.** After the first login, create the Root and Sub CA in
CA -> Core CA, otherwise every issuance form will return an error.

**Moving an installation means two files:** `db/database.db` and `config.yaml`.

## If you need implementation details

Component design, database schema, protocols and implementation specifics are covered
in the [technical documentation](../technical%20documentation/contents.md).
