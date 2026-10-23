# Polaris

Polaris is the single durable Almanac and application-credential authority. Astrolabe submits management writes; Stars discover Polaris through Pulsar
and initiate synchronization. Polaris is a Go service using its own SQLite database.

[Deployment](../docs/deployment.md) · [Astrolabe API](../astrolabe/README.md) · [Architecture](../docs/architecture.md)

## Start the authority

With Pulsar available, provision a distinct internal identity and unused state path:

```bash
bin/polaris --listen=10.0.0.10:7444 --super=10.0.0.10:7440 \
  --galaxy=example --identity=/etc/astra/polaris \
  --state=/var/lib/astra/polaris.db --init=true
```

Remove `--init=true` after initialization. The parent directory must already exist. `--advertise` defaults to `--listen`; endpoints must be concrete
canonical IP:port values. The identity directory contains `ca.pem`, `cert.pem`, `key.pem`, `admission.pub` and `login.json`, with a Pulsar account
authorized for `polaris`.

The database binds the Pulsar account name, Galaxy and advertised endpoint. Restart with that same binding and database. Only one authority is
supported; there is no election, automatic standby promotion or endpoint migration.

## Commit and synchronization

Polaris assigns authority through strictly checked Scope versions. The management request proposes the next version; successful commit advances one
Scope atomically, including a multi-key batch. A receipt follows durable commit. It does not wait for every Star to install the change.

Stars use bounded history to catch up, then a complete snapshot when the requested interval is unavailable. Partial snapshots never count as
installation. Version reconciliation concerns complete installed state, not enqueued sends. Slow or disconnected Stars do not block all management
writes.

`--snapshot-bytes` defaults to 256 MiB for shared snapshot preparation and active data. History, snapshots and streams are bounded; quota rejection is
explicit. Polaris stores neither Catalog/Ephemeris nor management accounts/sessions.

## Recovery

Use supported local storage, not a network share. Polaris uses SQLite WAL with `synchronous=FULL` and process-level exclusivity. Main-file, WAL and
SHM state must be treated consistently; never delete crash-left journals to bypass recovery.

Copying only a live main database file is not a backup. Use SQLite's consistent backup facilities under an operator-reviewed procedure, or a correctly
quiesced complete state copy. 0.1.0 provides no backup-management API or automatic restore workflow.

Restoring an old authority while Stars retain newer versions is not normal restart. A lower authority version cannot overwrite a newer installed
version; equal-version divergence after unauthorized rollback is not a supported recovery mode. Stop affected writes and reconcile the deployment
rather than increasing versions or reinitializing silently.

Storage failure or uncertain commit requires diagnosis. Do not convert every SQL error or response timeout into an assertion that the transaction was
unapplied. See [troubleshooting](../docs/troubleshooting.md) and the versioned [CLI](main.go).
