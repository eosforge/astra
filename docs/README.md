# Astra documentation

These guides describe the delivered 0.1.0 interfaces and deployment boundaries.

| Task | Guide |
| --- | --- |
| Understand components and data guarantees | [Architecture](architecture.md) |
| Install binaries and deploy three Stars | [Deployment](deployment.md) |
| Compile services or an SDK | [Build](build.md) |
| Diagnose startup, authentication or recovery | [Troubleshooting](troubleshooting.md) |
| Inspect package identity, platforms and notices | [Releases](releases.md) |
| Locate component tests and explicit reproduction entries | [Tests](../tests/README.md) |
| Review recorded tests and unverified boundaries | [Validation summary](../CHANGELOG.md#validation-summary) |
| Contribute or report a community concern | [Contributing](../CONTRIBUTING.md), [Code of Conduct](../CODE_OF_CONDUCT.md) |
| Configure application-facing nodes | [Star](../star/README.md) |
| Configure admission and time | [Pulsar](../pulsar/README.md) |
| Operate the durable authority | [Polaris](../polaris/README.md) |
| Manage data and credentials through HTTP | [Astrolabe](../astrolabe/README.md) |
| Integrate a C++ application | [Comet C++](../comet/cpp/README.md) |
| Integrate a Go application | [Comet Go](../comet/go/README.md) |
| Inspect transport contracts | [Protocols](../proto/README.md) |

For project participation, read [CONTRIBUTING](../CONTRIBUTING.md), [SECURITY](../SECURITY.md) and the [changelog](../CHANGELOG.md).

Deployment commands require provisioned identities, reachable hosts and an existing build or release package. SDK examples require an existing Star
and issued application credentials. The release workflow does not execute these deployment examples or start a cluster.

The binary package includes these Markdown guides in the same relative layout. Links to implementation files open the versioned source on GitHub; a
binary package is not a full source checkout.
