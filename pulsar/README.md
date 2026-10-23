# Pulsar

Pulsar is the C++ infrastructure admission and continuous-time service. It authenticates infrastructure accounts, issues credentials, stores
membership in SQLite and exposes a separate time-sampling endpoint for Stars. Comet applications connect to Star, not Pulsar.

[Deployment](../docs/deployment.md) · [Protocols](../proto/README.md) · [Troubleshooting](../docs/troubleshooting.md)

## First startup

Provision the identity files, create a deployment-owned state directory and choose an unused database path:

```bash
bin/pulsar --listen=10.0.0.10:7440 --pulse-listen=10.0.0.10:7441 \
  --galaxy=example --identity=/etc/astra/pulsar \
  --state=/var/lib/astra/pulsar.db --init=true
```

Remove `--init=true` for normal restarts. Initialization refuses existing databases and recovery sidecars; normal startup refuses a missing database.
Both concrete listener IPs must be covered by the deployed certificate's IP SANs.

| Material | Format |
| --- | --- |
| `ca.pem`, `cert.pem`, `key.pem` | Internal TLS trust, certificate and private key |
| `admission.key` | PKCS#8 Ed25519 issuer private key |
| `admission.pub` | Matching raw 32-byte Ed25519 public key |
| `accounts.json` | Array of 1..64 accounts with `username`, `salt`, `hash`, `roles` |

Account salts and hashes are hexadecimal encodings of 16 and 32 bytes. Derive hashes with PBKDF2-HMAC-SHA256, 600000 iterations. Delivered role names
are `star`, `polaris` and `astrolabe`; grant each account only the required roles. See [identity
provisioning](../docs/deployment.md#account-file-formats) for formats and offline derivation.

## Capacity and operation

`--max-members` defaults to 64 per role, with a 1..4096 range. `--max-starts` defaults to 65536 retained startup records, with a 1..1000000 range.
Exhaustion rejects admission; it does not silently discard old startup or generation evidence.

Membership entries describe registered deployments, not expiring health leases. A new advertised endpoint changes deployment identity and consumes
another slot. Keep stable endpoints; 0.1.0 has no automatic member-retirement or endpoint-migration workflow.

Accounts are read at startup; changes require a controlled restart. Pulsar stores no Almanac, Catalog or Ephemeris payloads. Host clock
synchronization is external: Pulse samples time but does not configure or discipline the operating-system clock.

## Recovery

Use the same Galaxy, issuer identity and SQLite state for normal restart. The ledger restores membership, generations and startup-idempotency
relationships before serving registration. Wrong identity, unsupported schema or corruption fails startup rather than creating a new cluster.

The database uses rollback-journal DELETE and `synchronous=EXTRA`, with a separate process-exclusivity lock. Preserve recovery files after a crash.
Filesystem/device durability still matters; SQLite transactions are not protection against unauthorized backup rollback.

An old backup must not overwrite a live issuer: it can discard generation and replaced-startup evidence. There is no automatic legacy journal import,
trust-domain reset or rollback protocol. Preserve the original state and investigate rather than deleting files to force startup.

`--help` and `--version` do not load identities or start services. See the versioned [entry
implementation](src/server.cpp).
