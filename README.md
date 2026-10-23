# Astra

Astra provides distributed service discovery and state synchronization. Applications use the native Comet SDKs to publish short-lived data, discover
live registrations, and subscribe to authoritative configuration.

## Components

| Component | Purpose | Guide |
| --- | --- | --- |
| Star | Replicated application-facing views and dynamic writes | [Star](star/README.md) |
| Pulsar | Infrastructure admission, durable membership and continuous time | [Pulsar](pulsar/README.md) |
| Polaris | Single durable configuration and application-credential authority | [Polaris](polaris/README.md) |
| Astrolabe | Authenticated management HTTP API | [Astrolabe](astrolabe/README.md) |
| Comet C++ | C++23 application SDK | [Install and use](comet/cpp/README.md) |
| Comet Go | Independent Go application module | [Install and use](comet/go/README.md) |

## Start here

1. Read the [architecture and data guarantees](docs/architecture.md) to choose Almanac, Catalog or Ephemeris.
2. Download [Astra 0.1.0](https://github.com/eosforge/astra/releases/tag/v0.1.0) and verify `SHA256SUMS`.
3. Follow the [deployment guide](docs/deployment.md) for identities, startup order and a three-Star topology.
4. Use [Astrolabe](astrolabe/README.md) to provision application credentials, then follow the C++ or Go SDK guide.

The Linux x86-64 archive includes `star`, `pulsar`, `polaris`, `astrolabe`, Comet C++ headers/library/CMake exports, matching GCC runtime libraries,
public documentation and third-party notices. Keep its `bin/` and `lib/` directories together. The build uses Debian 13; consult `build-manifest.json`
for the exact glibc requirement and source commit. The C++ development package requires matching external dependencies. Comet Go is distributed as
source.

```bash
sha256sum --check SHA256SUMS
tar -xzf astra-0.1.0-linux-x86_64.tar.gz
```

These commands assume all three release assets have been downloaded into one directory. Cluster identities and persistent databases are
operator-owned; read the deployment guide before starting services.

## Documentation

- [Documentation index](docs/README.md)
- [Build from source](docs/build.md)
- [Test source and execution guide](tests/README.md)
- [Version validation summary](CHANGELOG.md#validation-summary)
- [Troubleshooting and recovery](docs/troubleshooting.md)
- [Protocol reference](proto/README.md)
- [Release contents, provenance and compatibility](docs/releases.md)
- [Changelog](CHANGELOG.md), [contributing](CONTRIBUTING.md), [code of conduct](CODE_OF_CONDUCT.md) and [security](SECURITY.md)

## 0.1.0 scope

The server release targets Linux x86-64. The standalone C++ SDK also has a Windows/MSVC source build entry; this release does not provide Windows
binaries. The Admin frontend, Planet scaffold and Moon are outside this delivery.

Catalog and Ephemeris use finite lifetimes and memory replication. They are not durable application databases. Polaris is a single authority without
automatic failover. Version 0.1.0 is an initial release; review its recovery and compatibility limits before deployment.

GitHub Actions builds the versioned source and checks installed linkage and package hashes. That result is not a claim that all product tests,
production qualification, protected-CI attestation or cryptographic signing have completed. See the [verification
boundary](docs/releases.md#verification-boundary).

## License

Owned Astra code and documentation are licensed under the [MIT License](LICENSE). Third-party code and bundled runtimes retain their original
licenses, notices and exceptions; see [license distribution](docs/releases.md#licenses).
