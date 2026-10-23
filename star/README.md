# Star

Star is Astra's application-facing node. It serves Almanac reads, accepts Catalog publications and Ephemeris registrations, and replicates dynamic
data with peers in its Galaxy.

[Deployment](../docs/deployment.md) · [Architecture](../docs/architecture.md) · [Comet C++](../comet/cpp/README.md) · [Comet
Go](../comet/go/README.md)

## Start a node

After Pulsar and Polaris are configured, run this deployment example with provisioned identities:

```bash
bin/star --listen=10.0.0.11:7442 --comet=10.0.0.11:7443 \
  --super=10.0.0.10:7440 --galaxy=example --group=east \
  --identity=/etc/astra/star-a --comet-identity=/etc/astra/comet-a
```

| Option | Meaning |
| --- | --- |
| `--listen` | Internal numeric IP:port; wildcard binding requires an explicit reachable advertised address |
| `--advertise` | Reachable internal numeric endpoint; defaults to the bound listener |
| `--super` | Pulsar admission host:port |
| `--galaxy`, `--group` | Galaxy and locality preference; group defaults to `default` |
| `--identity` | Internal TLS, admission public key and login files |
| `--comet` | Separate application listener; omitted means no application listener |
| `--comet-identity` | Application TLS `cert.pem` and `key.pem` |
| `--auth`, `--tls` | Application authentication and TLS; both default to `true` |
| `--metrics` | Optional read-only HTTP metrics listener; disabled by default |
| `--max-members` | Per-role capacity including this Star; default 64, range 1..4096 |

`--help` lists remaining timeouts and admission budgets. Application security flags affect the Comet listener only. TLS-disabled configurations must
not also specify a Comet certificate directory. Protect any enabled metrics listener with deployment-level access controls.

## Readiness and data

Star registers with Pulsar and discovers Polaris and peers. Almanac synchronization uses the discovered authority; applications do not configure a
second Polaris address. A listener opening is not proof of admission or data readiness. Observe each SDK role's state and operation result.

The standard topology has three Stars, each accepting local writes. Connect separate application clients to each endpoint when validating cross-node
subscriptions and bidirectional source replication; configuring three addresses on one client does not generate three concurrent writers.

Almanac is durable at Polaris. Catalog and Ephemeris are memory data with finite lifetimes; losing all replicas loses those views. Scope snapshots and
batches are published only when complete. Different subscriptions and nodes can observe updates at different times.

## Shutdown and recovery

Stop through the process supervisor using SIGINT or SIGTERM and allow the configured shutdown budget to drain owned work. Restart with the same
infrastructure identity and stable advertised address. Polaris restores Almanac through synchronization; live peers may supply dynamic state, subject
to actual expiry and availability.

Do not promise persistence for Catalog/Ephemeris or infer readiness from membership alone. See [troubleshooting](../docs/troubleshooting.md) and the
versioned [CLI definitions](../common/src/options.hpp).
