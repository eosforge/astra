# Comet Go SDK

Comet is Astra's native Go application SDK. It connects to a Star's application endpoint and exposes Client, Reader, Subscriber, Publisher, Observer
and Beacon without requiring generated protocol types in application code.

[Architecture](../../docs/architecture.md) · [Deploy a Star](../../docs/deployment.md) · [Provision
credentials](../../astrolabe/README.md#publish-data-and-credentials)

## Install

Use Go 1.27.0 or newer. The module has its own `go.mod`:

```bash
go get github.com/eosforge/astra/comet/go@v0.1.0
```

This command explicitly downloads the module and required dependencies. To prohibit automatic toolchain acquisition, select a suitable existing Go
installation and set `GOTOOLCHAIN=local`. An offline environment needs the matching module cache first.

The module tag is `comet/go/v0.1.0`; the argument to `go get` remains `@v0.1.0`. The root `v0.1.0` tag versions the complete Astra distribution. For
local development, an application's `go.mod` may temporarily use `replace github.com/eosforge/astra/comet/go => /absolute/path/to/astra/comet/go`;
remove that local path before distributing the application.

This initial version has been republished. Previously cached `v0.1.0` content can differ from the current Git tag; review the
[republication compatibility boundary](../../docs/releases.md#republication-compatibility) before relying on the version string alone.

## Minimal Catalog publisher

This complete example requires an existing, ready Star, a provisioned API key/secret and a PEM CA bundle for its application certificate. Set
`COMET_ENDPOINT`, `COMET_KEY`, `COMET_SECRET_FILE` and `COMET_CA_FILE` through your deployment environment. The secret file contains exact raw bytes,
with no unintended trailing newline.

```go
package main

import (
    "context"
    "fmt"
    "os"
    "time"

    comet "github.com/eosforge/astra/comet/go"
)

func main() {
    if err := run(); err != nil {
        fmt.Fprintln(os.Stderr, err)
        os.Exit(1)
    }
}

func run() error {
    secret, err := os.ReadFile(os.Getenv("COMET_SECRET_FILE"))
    if err != nil {
        return err
    }
    ca, err := os.ReadFile(os.Getenv("COMET_CA_FILE"))
    if err != nil {
        return err
    }
    client, err := comet.New(comet.Options{
        Endpoints: []string{os.Getenv("COMET_ENDPOINT")},
        Key: os.Getenv("COMET_KEY"), Secret: secret, CA: ca,
    })
    if err != nil {
        return err
    }
    defer func() {
        client.Close()
        // Cleanup has a fresh budget, independent of the request's deadline.
        drain, cancel := context.WithTimeout(context.Background(), 5*time.Second)
        defer cancel()
        if err := client.Wait(drain); err != nil {
            fmt.Fprintln(os.Stderr, "cleanup:", err)
        }
    }()
    publisher, err := client.Publisher(comet.Scope{Sector: "example", Spectrum: "workers"})
    if err != nil {
        return err
    }
    defer publisher.Close()
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
    defer cancel()
    receipt, err := publisher.Update(ctx, []comet.Entry{
        {Key: "worker-a", Data: []byte("ready")},
    }, 30*time.Second)
    if err != nil {
        return err
    }
    fmt.Println("committed at:", receipt.Instance, "version:", receipt.Version)
    return nil
}
```

`New` validates local configuration and starts the shared client; it does not prove login or remote readiness. The write result confirms only the
attached Star's commit. The record expires unless the application submits another explicit update. Closing Publisher does not immediately delete it.

The source [basic example](examples/basic/main.go) demonstrates all six roles and cancellation.
It reads the secret from `COMET_SECRET` and uses system trust; adapt secret delivery and `Options.CA` for your deployment. It never creates a product
service. Documentation examples are deployment-dependent and are not executed by release packaging.

## Choose a role

| Factory | Operation and lifetime |
| --- | --- |
| `Client.Reader(scope)` | Almanac `Watch`/`Changed` views; `Stop` ends the subscription |
| `Client.Subscriber(scope)` | Catalog `Watch`/`Changed` views; `Stop` ends the subscription |
| `Client.Publisher(scope)` | Atomic `Update(ctx, entries, ttl)`; `Close` stops the writer |
| `Client.Observer(scope)` | Local Ephemeris selection through `One`; `Stop` closes it |
| `Client.Beacon(ctx, scope, attr, data, ttl, beat)` | Waits for first registration; `Update`, optional `Tick`, automatic beat renewal; `Destroy` closes it |

Reader/Subscriber snapshots become visible only after complete installation. Empty data and missing keys differ. Observer estimates are local and do
not update Star. Beacon requires `0 < beat < ttl`; its Attr, TTL and beat are fixed at creation, while Update replaces Data.

## Security, failures and concurrency

TLS verification and authentication are enabled by default. `Options.CA` accepts PEM bytes; nil uses system trust. `Anonymous` and `Plaintext` are
explicit independent opt-outs that must match server policy. There is no automatic security downgrade.

`Options.Timeout` defaults to three seconds and accepts `(0, 1 minute]`. Context cancellation and deadlines limit individual operations. Inspect
`*comet.Error` with `errors.As`; `Code` describes the failure and `Effect` distinguishes `Unapplied` from `Unknown`. Never blindly replay an unknown
write. Publisher does not retain failed data for background submission; overlapping updates on one Publisher return busy.

Client sharing coalesces authentication. `Client.Secret` changes the secret for the same API key for later login, not the server's credential record.
A new secret cannot revive a closed client. A recovered Beacon retains its logical identity and last confirmed data within the documented failover
limits.

Keep callbacks short and nonblocking; callbacks from different roles may overlap. Do not perform synchronous SDK writes or wait for SDK cleanup inside
notification callbacks. Hand work to a bounded application executor. Delivered snapshots own their data; application retention still consumes memory.

`Stop`, `Close` and `Destroy` are logical shutdown requests. `Client.Wait` waits for actual local cleanup and must use a separate bounded context
outside callbacks. Remote removal is best effort; TTL remains the final cleanup boundary. See [public
source](.) and [protocol contracts](../../proto/README.md).
