# Protocol reference

[Architecture](../docs/architecture.md) · [Comet C++](../comet/cpp/README.md) · [Comet Go](../comet/go/README.md)

The checked-in `.proto` definitions are the versioned wire source of truth. Applications should normally use Comet; directly generated clients must
implement the same authentication, cursor, completion and failure contracts.

| Definition | Service boundary |
| --- | --- |
| [comet.proto](comet.proto) | Public Gateway Session and Almanac/Catalog/Ephemeris RPCs |
| [orbit.proto](orbit.proto) | Infrastructure registration, directory and admission credentials |
| [pulsar.proto](pulsar.proto) | Star-to-Pulsar four-timestamp time sampling |
| [polaris.proto](polaris.proto) | Internal authority commits/snapshots and Star Almanac synchronization |
| [astra.proto](astra.proto) | Internal Star sessions and source replication |

## Public application transport

`proto.comet.v1.Gateway/Session` authenticates application credentials and establishes the current application session. It is separate from internal
admission and from Astrolabe's HTTP cookie. TLS authenticates the server independently of the application API key/secret.

Almanac exposes Watch. Catalog exposes Query, Publish, Renew and Watch; the native Publisher API intentionally requires explicit updates rather than
automatically renewing records. Ephemeris exposes Create, Update, Renew, Remove and Watch. Internal authority mutation is not a public Comet write
path for Almanac.

Scopes contain byte-encoded `sector` and `spectrum`; the SDK requires valid bounded UTF-8 identifiers and reserves internal sectors beginning with
`__`. Payloads are bytes. Missing data, present empty data and an incomplete/unready view are distinct states.

## Commit and stream rules

A batch becomes visible only after full validation and commit. Snapshot pagination is transport, not permission to expose partial state. Watch
consumers retain the last complete cursor and install only complete snapshots or delta batches. A history gap requires a new baseline rather than
inventing missing transitions.

Catalog versions order content; they do not create a global multi-Star transaction order. Ephemeris registration generation and Data version serve
different purposes. A timed-out write may have committed; errors must retain whether the outcome is unknown or explicitly unapplied.

Beacon recovery uses an SDK-held capability, not UUID knowledge alone. Capabilities and secrets must not enter subscription output, replication
diagnostics or logs. Old target/generation messages cannot authorize new registration state.

## Infrastructure and compatibility

Pulsar registration binds the account, Galaxy and canonical endpoint, and provides the directory and Pulse endpoint. Membership is not a health lease.
Stars discover the unique Polaris authority through that directory and synchronize complete installed versions over internal streams.

Legacy role values retained in protocol definitions do not imply delivered Planet/Moon services. Internal transport is a service-to-service contract,
not an alternative unauthenticated application API.

Use matching 0.1.0 services and SDKs. Do not assume mixed-version interoperability, storage migration or compatibility with earlier experimental
layouts. Preserve field numbers and the [message-ID lock](message-ids.lock) when proposing
changes; generated files are updated through the pinned generator, not edited manually.

Exact fields and comments live in the linked definitions. [Astrolabe](../astrolabe/README.md) documents the separate management HTTP representation,
including decimal-string versions, Base64 payloads and NDJSON completion.
