# Install and deploy Astra

[Documentation](README.md) · [Architecture](architecture.md) · [Troubleshooting](troubleshooting.md)

## Install the binary package

Download these three files from the same [v0.1.0 release](https://github.com/eosforge/astra/releases/tag/v0.1.0):

| File | Purpose |
| --- | --- |
| `astra-0.1.0-linux-x86_64.tar.gz` | Four service executables, Comet C++ development files, GCC runtime libraries, this guide and licenses |
| `SHA256SUMS` | SHA256 checksums for the archive and build manifest |
| `build-manifest.json` | Source commit, toolchain, build environment, packaged file hashes and installed linkage |

Verify both downloaded files before extraction:

```bash
sha256sum --check SHA256SUMS
tar -xzf astra-0.1.0-linux-x86_64.tar.gz
cd astra-0.1.0-linux-x86_64
```

Use a Linux x86-64 host compatible with the recorded Debian 13/glibc build environment. The package supplies matching `libstdc++.so.6` and
`libgcc_s.so.1` under `lib/`; it does not bundle glibc. Keep `bin/` and `lib/` together when relocating the installation. The service executables are
`bin/star`, `bin/pulsar`, `bin/polaris` and `bin/astrolabe`.

Deployment identities, private keys, accounts and persistent databases are operator-supplied. The archive does not initialize a cluster or install a
system service. The commands below are deployment examples, not commands executed by the packaging workflow.

## Prepare deployment identities

Infrastructure admission, Comet application authentication and Astrolabe management login are separate trust boundaries:

| Consumer | Required material |
| --- | --- |
| Pulsar identity directory | `ca.pem`, `cert.pem`, `key.pem`, `admission.key`, `admission.pub`, `accounts.json` |
| Star, Polaris and Astrolabe internal identity directories | `ca.pem`, `cert.pem`, `key.pem`, `admission.pub`, `login.json` |
| Each Star's separate Comet identity directory | `cert.pem` and `key.pem` for its application-facing TLS listener |
| Astrolabe management login | Separate account JSON with `username`, `salt` and `hash`, selected by `--account` |
| Comet application | API key and secret issued through Astrolabe/Polaris, plus trust for the Star's business certificate |

`admission.key` is the Pulsar issuer's PKCS#8 Ed25519 private key; `admission.pub` is its raw 32-byte public key. Pulsar accounts authorize the
required infrastructure roles. Node `login.json` supplies that node's Pulsar account credentials. Keep private keys, passwords and account files
outside the source tree with restrictive access.

Account digests use PBKDF2-HMAC-SHA256 with 600000 iterations, a 16-byte salt and a 32-byte digest. The management account is separate from Pulsar
accounts and Comet secrets. Account changes require a controlled restart; there is no online account provisioning or automatic credential fallback.

Use concrete canonical `IP:PORT` endpoints in this topology, covered by the corresponding certificate IP SANs. Certificates used for externally
visible DNS names must also cover those names. Provision identities for the actual deployment; files under `tests/fixtures` are public test identities
and must not become deployment credentials.

Star's `--listen` is its internal endpoint; `--comet` is a separate application endpoint. Business authentication and TLS default to enabled.
`--auth=false` and `--tls=false` explicitly affect only the Comet listener, not infrastructure admission or internal TLS. Credentials are distributed
from Polaris through internal Almanac synchronization; a local credential file is not an alternative authority.

## Start the services

Use one Pulsar issuer, one Polaris authority, and at least three Stars for the standard system topology. Each Star accepts its own local writes;
subscriptions and source replication span nodes. A Star's listener opening alone does not prove admission, authority synchronization or peer
readiness.

The following addresses are examples. Supply your own reachable addresses, identities, state directories and certificates. Run each command as a
separately supervised process on the indicated host.

### 1. Pulsar admission and time

For a new cluster only, create the deployment-owned state directory and choose an unused database path:

```bash
bin/pulsar --listen=10.0.0.10:7440 --pulse-listen=10.0.0.10:7441 \
    --galaxy=example --identity=/etc/astra/pulsar \
    --state=/var/lib/astra/pulsar.db --init=true
```

Remove `--init=true` for every subsequent restart. Both listeners must be reachable by Stars and covered by the Pulsar certificate. Pulsar provides
registration and continuous time, not Almanac/Catalog/Ephemeris storage. Host clock synchronization remains a deployment responsibility; Pulse does
not configure or discipline the host clock.

### 2. Polaris authority

Initialize its separate database once:

```bash
bin/polaris --listen=10.0.0.10:7444 --super=10.0.0.10:7440 \
    --galaxy=example --identity=/etc/astra/polaris \
    --state=/var/lib/astra/polaris.db --init=true
```

Remove `--init=true` after initialization. Polaris is the single durable Almanac authority. Its initial deployment binds the Pulsar account name,
Galaxy and advertised endpoint to the database. Restart with the same database and binding; there is no automatic election, standby promotion or
endpoint migration. Astrolabe performs management writes, and Stars initiate internal synchronization to Polaris discovered through Pulsar.

### 3. Three Stars

Run Star A on `10.0.0.11`:

```bash
bin/star --listen=10.0.0.11:7442 --comet=10.0.0.11:7443 \
    --super=10.0.0.10:7440 --galaxy=example --group=east \
    --identity=/etc/astra/star-a --comet-identity=/etc/astra/comet-a
```

Run Star B on `10.0.0.12` and Star C on `10.0.0.13` with their own internal and Comet identities:

```bash
bin/star --listen=10.0.0.12:7442 --comet=10.0.0.12:7443 \
    --super=10.0.0.10:7440 --galaxy=example --group=east \
    --identity=/etc/astra/star-b --comet-identity=/etc/astra/comet-b

bin/star --listen=10.0.0.13:7442 --comet=10.0.0.13:7443 \
    --super=10.0.0.10:7440 --galaxy=example --group=west \
    --identity=/etc/astra/star-c --comet-identity=/etc/astra/comet-c
```

Allow the intended infrastructure connections and Pulsar admission/time traffic between these hosts. Applications connect to the `7443` Comet
endpoints, not the `7442` peer endpoints. A different `--advertise` can identify a reachable internal endpoint when it differs from `--listen`; it is
still subject to identity validation.

### 4. Astrolabe management

Supply a separate management account file and an HTTPS public origin covered by the deployed certificate:

```bash
bin/astrolabe --listen=10.0.0.10:7445 --super=10.0.0.10:7440 \
    --galaxy=example --identity=/etc/astra/astrolabe \
    --account=/etc/astra/management-account.json \
    --public=https://management.example:7445
```

Astrolabe exposes the management HTTP API; the Admin frontend is a separate, excluded delivery. Login uses `POST /api/session`; subsequent requests
use the HttpOnly `astra-session` cookie. Login, logout and mutations require an allowed `Origin` and `X-Astra-Request: 1`; JSON requests use
`application/json`. `--origins` adds explicit browser origins. Sessions expire eight hours after issuance and are lost on process restart.

Use management to publish Almanac data and issue Comet application credentials. Empty credential state does not enable anonymous Comet access. The
concrete HTTP request/response types and handlers are in [Astrolabe API guide](../astrolabe/README.md). Management version numbers are decimal
strings; a write may return a committed, unapplied or unknown outcome. Login success does not prove Pulsar/Polaris readiness.

## Account file formats

Provision certificates through your deployment PKI. Internal peers need certificate material usable for their TLS client and server roles, with SANs
for the actual endpoints. Comet uses a separate Star server certificate. `admission.pub` is raw Ed25519 public-key bytes, not a PEM certificate or PEM
public-key file. Keep the corresponding issuer private key only at Pulsar.

Pulsar `accounts.json` uses an array. This is a structural template; replace the placeholders with correctly derived hexadecimal values:

```json
[
  {"username":"star-a","salt":"<32-hex-characters>","hash":"<64-hex-characters>","roles":["star"]},
  {"username":"authority","salt":"<32-hex-characters>","hash":"<64-hex-characters>","roles":["polaris"]},
  {"username":"management-node","salt":"<32-hex-characters>","hash":"<64-hex-characters>","roles":["astrolabe"]}
]
```

Add the remaining node accounts with their actual roles. A node's protected `login.json` contains exactly its Pulsar `username` and original
`password`:

```json
{"username":"star-a","password":"<unique-node-password>"}
```

Astrolabe's separate management account is a single object with `username`, `salt` and `hash`, without `roles`. The following offline Python snippet
derives one account's digest from an interactive password. It does not generate TLS or admission signing keys and does not modify running services:

```python
import getpass
import hashlib
import json
import secrets

username = input("Account name: ")
password = getpass.getpass("Password: ").encode("utf-8")
salt = secrets.token_bytes(16)
digest = hashlib.pbkdf2_hmac("sha256", password, salt, 600000, dklen=32)
print(json.dumps({"username": username, "salt": salt.hex(), "hash": digest.hex()}))
```

Store its output as the management account, or add the appropriate `roles` array and place it in Pulsar's account array. Use valid account names and
nonempty passwords; node passwords are limited to 1024 bytes. Each account needs its own salt and secret. Never use example placeholders or source
test credentials as live identities.

## Restart and recovery

Run each service under an operator-managed supervisor with persistent state directories and protected identities. After first initialization, omit
`--init=true` permanently for that database. Stop through SIGINT/SIGTERM and allow bounded shutdown before terminating the process.

- Pulsar restores membership, generations and startup bindings from its own ledger. Preserve the issuer key, Galaxy and state together.
- Polaris restores authoritative data from its separate database. Preserve the account/Galaxy/endpoint binding, WAL and other recovery files. It has no automatic standby or rollback protocol.
- Star restores Almanac by synchronizing with Polaris. Catalog and Ephemeris remain finite-lifetime memory data; surviving peers may supply still-valid content, but this is not durable storage.
- Astrolabe loses management sessions on restart. Applications keep their own credentials and should follow each SDK's recovery and unknown-write rules.

Do not delete a database or journal to force startup. Do not restore an old backup into a live trust domain with newer generations or versions. Use an
operator-reviewed consistent backup/restore procedure; 0.1.0 does not provide automatic cluster-wide restore. See
[Pulsar](../pulsar/README.md#recovery), [Polaris](../polaris/README.md#recovery) and [troubleshooting](troubleshooting.md).
