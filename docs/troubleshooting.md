# Troubleshooting

[Documentation](README.md) · [Deployment](deployment.md) · [Security](../SECURITY.md)

## Diagnose by boundary

| Symptom | Check |
| --- | --- |
| Loader cannot find `libstdc++` or `libgcc_s` | Keep package `bin/` and `lib/` together; inspect the manifest and the actual resolved library paths |
| `GLIBC_... not found` | The host is older than the recorded build baseline; use a compatible host or an explicitly supported source build |
| TLS handshake or hostname verification fails | CA chain, certificate validity, SAN matching the dialed host/IP, and the correct internal or Comet identity directory |
| Infrastructure admission is rejected | Node `login.json`, Pulsar role grants, Galaxy, advertised endpoint and admission public key |
| Listener is open but reads are unready | Pulsar admission, unique Polaris discovery, authority recovery and complete Star bootstrap |
| Comet authentication fails | Application API key/secret and Star credential synchronization; management/Pulsar passwords are different |
| Catalog record expires | Each update supplies a TTL; Publisher does not renew automatically |
| Beacon becomes uncertain | Time quality, target connectivity and lease budget; a late receipt does not reset the original TTL budget |
| Management returns origin/session errors | Exact `Origin`, `X-Astra-Request: 1`, HTTPS cookie handling and session expiry |
| Snapshot HTTP response ends early | Require the NDJSON completion marker and successful end; never install a partial result |
| `busy` or capacity failure | Reader/writer/snapshot budgets, retained views and slow callbacks; do not spin in an unlimited retry loop |
| Database is missing, locked or mismatched | Correct persistent path and deployment binding; another process, wrong state or missing initialization |

## Unknown write results

A timeout or disconnect may occur after a write committed. Inspect the SDK error's effect or management response's `effect` separately from its error
category. `unknown` is not `unapplied`. Reconcile application state before deciding whether to submit another write; do not blindly replay
non-idempotent work.

Publisher retains no failed payload for later submission. Beacon recovery uses its last confirmed state and may temporarily expose older data after
failover. Neither behavior converts an earlier unknown result into a confirmed failure or success.

## Restart and state

Normal restart uses the original databases and identities without `--init=true`. Initialization is only for a new cluster/database. Do not remove
SQLite journals, sidecars, generation records or lock files to bypass a startup failure. Establish process ownership and state consistency first.

Polaris WAL files can contain committed data. A live main-file copy is not a consistent backup. Old backups cannot be silently restored into a running
cluster with newer Stars. See [Polaris recovery](../polaris/README.md#recovery) and [Pulsar recovery](../pulsar/README.md#recovery).

## Useful issue details

Record version and commit from `build-manifest.json`, OS/architecture, compiler/libc where relevant, component, non-secret configuration, a minimal
reproduction, timestamps and the exact stable error category. Compare archive checksums before investigating a suspected mixed-version install.

Redact secrets, cookies, private keys and payloads. Use [Issues](https://github.com/eosforge/astra/issues) for ordinary defects and the [security
process](../SECURITY.md) for vulnerabilities. A listener log is not evidence of end-to-end readiness, and a successful compile is not a runtime test.
