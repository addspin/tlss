# 01. First run and initialization

The steps from an unpacked binary to a working certificate authority.

## What happens on the first run

On startup the application asks three questions in the console:

| Question | Purpose |
|---|---|
| **login** | Account name for the web interface |
| **password** | Password. A key is derived from it and used to encrypt the database master key |
| **salt** | Salt for PBKDF2 |

These values cannot be recovered. The master key that encrypts every private key in
the database is itself encrypted with the password, and there is no backup copy.
**Losing the password means losing all keys.**

If you set `login.authConfig: true` in the configuration, the questions are skipped and
the values are taken from the file - convenient during development, but not something
you want in production, see [02-production-setup.md](02-production-setup.md).

After that the application does the rest on its own:

1. Creates the `db`, `root_ca_tlss`, `https`, `crlFile` and `logs` directories
2. Generates `config.yaml` next to the executable
3. Creates the tables in `db/database.db`
4. Generates the master key and stores it encrypted
5. Generates the `Default` SSH key used to connect to servers
6. Starts three listeners: web interface, CRL/OCSP and EST

## Ports after installation

| Listener | Port | Protocol |
|---|---|---|
| Web interface and API | 43000 | per `app.protocol` |
| CRL and OCSP | 8080 | HTTP |
| EST | 43001 | always TLS |

The first run uses the default configuration and starts on an unsecured port - the
address, protocol and certificates have to be sorted out before real use.

## Creating the certificate authority

After the first login you land on the CA generation page. **Until the Root and Sub CA
exist, no certificate can be issued** - every form will fail with an error about
extracting the signing CA.

The order is:

1. Section **CA -> Core CA**
2. Fill in the Root CA fields: Common Name, organization, validity period, key length
3. Create the Sub CA - it is the one that signs all end-entity certificates

The Root CA is stored encrypted in the database and is never exported. The Sub CA and
all other certificates can be downloaded.

## Verifying that everything came up

```bash
# Web interface
curl -k https://tlss.lv.local:43000/overview

# CRL - appears once the CA is created
curl http://tlss.lv.local:8080/api/v1/crl/subca/pem | head -3

# OCSP - only answers a well-formed request, see the testing documentation
curl -i http://tlss.lv.local:8080/ocsp
```

On a successful start the log contains lines about the three servers and about the
intermediate CA being loaded:

```
Starting TLSS UI server with HTTPS
Starting HTTP CRL server
Starting EST mTLS server
ExtractCA: Intermediate CA certificate and key successfully extracted
```

## What to do next

| Task | Interface section |
|---|---|
| Issue a server certificate | Servers certs -> Add servers certs |
| Issue a client certificate | Clients certs -> Add clients certs |
| Set up automated issuance for devices | EST -> Add EST users |
| Create a key for automation | API -> API keys |
| Upload a third-party CA | CA -> External CA |

Before issuing certificates, create the object they attach to: a server
(Servers certs -> Add servers) or an entity (Clients certs -> Add entities).

## Moving an installation

The whole state is two files: the `db/database.db` database and `config.yaml`. Copy
them to another machine together with the binary and the installation keeps working.
The administrator password is still required - without it the database cannot be
decrypted.

---

Next: [02-production-setup.md](02-production-setup.md) - what to change before going
live.
