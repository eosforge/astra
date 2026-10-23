# Astrolabe

Astrolabe is the management HTTP service for Astra. It authenticates an operator, discovers infrastructure through Pulsar and sends authoritative
changes to Polaris. It keeps management sessions in memory and has no management database. The Admin frontend is not part of 0.1.0.

[Deployment](../docs/deployment.md) · [Polaris](../polaris/README.md) · [Security](../SECURITY.md)

## Start management

```bash
bin/astrolabe --listen=10.0.0.10:7445 --super=10.0.0.10:7440 \
  --galaxy=example --identity=/etc/astra/astrolabe \
  --account=/etc/astra/management-account.json \
  --public=https://management.example:7445
```

Provision internal TLS/admission files and a Pulsar account with the `astrolabe` role. The separate management account file contains `username`,
hexadecimal `salt` and hexadecimal `hash`; see [account formats](../docs/deployment.md#account-file-formats). The TLS certificate must cover the
actual listener and public hostname.

`--public` is the exact externally visible API origin. `--origins` adds explicit comma-separated allowed browser origins. `--http=true` permits
plaintext only on a loopback listener behind a separately configured proxy; infrastructure traffic remains TLS. `--crosssite=true` explicitly selects
cross-site cookies and requires an HTTPS public origin. `--sessions` defaults to 4096, with a 1..4096 range.

## HTTP API

Management data routes require a valid `astra-session` cookie; session lookup checks that cookie and logout is idempotent. Login, logout and mutations
require an allowed `Origin` and exactly `X-Astra-Request: 1`. JSON input uses `Content-Type: application/json`. Sessions expire eight hours after
issuance and disappear on restart. Logging in proves management authentication, not Polaris readiness.

| Method and route | Purpose |
| --- | --- |
| `POST /api/session` | Login with JSON `username` and `password`; sets HttpOnly session cookie |
| `GET /api/session` | Inspect current session |
| `DELETE /api/session` | Logout |
| `GET /api/nodes` | Infrastructure directory observations |
| `GET /api/metrics` | Configured, bounded metric observations |
| `GET /api/almanac` | Complete Scope/version inventory |
| `GET /api/almanac?sector=...&spectrum=...` | Stream one Scope snapshot as NDJSON |
| `POST /api/almanac` | Commit one key or an atomic batch at the next authority version |
| `GET /api/credentials` | Stream credential keys with secrets redacted |
| `POST /api/credentials` | Set or erase one application credential at the next credential-Scope version |

The optional `--metrics` file maps Star endpoints to protected metrics URLs. Missing or unavailable observations must not be interpreted as zero
utilization or healthy service.

## Login example

Create a protected local JSON file containing the management `username` and `password`, and supply the deployed CA. The following commands contact an
already running deployment; they do not start one:

```bash
umask 077
curl --fail-with-body --cacert /etc/astra/management-ca.pem \
  -c /run/astra-management.cookies \
  -H 'Origin: https://management.example:7445' \
  -H 'X-Astra-Request: 1' -H 'Content-Type: application/json' \
  --data-binary @/run/astra-management-login.json \
  https://management.example:7445/api/session

curl --fail-with-body --cacert /etc/astra/management-ca.pem \
  -b /run/astra-management.cookies \
  https://management.example:7445/api/almanac
```

Use an operator-owned directory accessible only to that account for credential and cookie files. The `/run/` paths are examples; choose writable
protected paths for your environment. Remove temporary login material and cookies when no longer required.

## Publish data and credentials

A new `example/config` Scope can receive this first write; for an existing Scope, read its current version and propose exactly the next version:

```json
{"sector":"example","spectrum":"config","version":"1","key":"greeting","value":"aGVsbG8="}
```

`value` is standard Base64 for the raw bytes (`hello` here). An empty string represents a present empty value. To delete, provide `"erase":true`
instead of `value`. A batch uses `changes` containing unique `key` plus `value` or `erase` entries, with no top-level key/action. Sectors beginning
with `__` are reserved.

Write the request to a file and POST it with the cookie, Origin and request marker shown above. Successful commits return `effect: "committed"` and a
Scope/version `position`. Versions are canonical decimal **strings**, not JSON numbers. A timeout or lost response may yield `unknown`; do not
automatically retry with a new version.

Application credentials use a separate protected JSON request file:

```json
{"key":"example-app","secret":"<standard-base64-of-your-secret-bytes>","version":"<next-credential-scope-version>"}
```

This is a template, not a runnable credential. Read `/api/credentials` for its completed snapshot version, choose the next version and POST to that
route. The empty initial Scope is version `0`, so its first write uses `"1"`. All credentials share that Scope's sequence. A secret is 1..4096 bytes
before Base64 encoding; supply the **decoded bytes** to Comet. Deletion uses `erase:true` instead of `secret`. GET never returns the secret.

For streamed snapshots, consume NDJSON through the terminal `complete` record and successful end. An `error` record or premature EOF is not a complete
snapshot. Credential changes propagate through Polaris and Stars; a management receipt does not mean all existing Star sessions have already observed
the change.

## Failure and recovery

Keep management login separate from infrastructure and application credentials. Restarting Astrolabe invalidates its cookies but does not reset
Polaris data. A disconnected authority should produce an unavailable/error result, not an empty successful view. See
[troubleshooting](../docs/troubleshooting.md).

The versioned [HTTP handlers](internal/web) define exact response fields, request limits and
error mapping.
