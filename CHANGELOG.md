# Changelog

## 0.1.0

Initial release, republished from the reviewed source tree:

- Star: service discovery, configuration views, Catalog publication and Ephemeris registrations.
- Pulsar: infrastructure admission, persistent membership and continuous-time sampling.
- Polaris: persistent configuration authority. Astrolabe: authenticated management API.
- Comet C++ and Go SDKs.
- Linux x86-64 binaries, checksums, build manifest, component guides and test source.

Admin, Planet and Moon are outside this release. See [release scope and compatibility](docs/releases.md).

### Source and SDK updates

- Restore Comet Go boundary tests, a Comet C++ shutdown-drain test and a Pulsar commit-recovery test.
- Add bounded Go/Python CI for pull requests and `main`, issue/PR templates and a code of conduct.
- Correct repository-relative documentation links and source links in binary packages.
- Use English source comments and verification notes, with equivalent UTF-8 test inputs.
- Rename C++ enum items to PascalCase, including the public Comet enums. Old names have no compatibility aliases; update source callers before rebuilding. Enum values and wire formats are unchanged.
- Isolate Go build caches from source discovery, correct coverage and mutation-build inputs, and prepare complete offline license inputs without changing maintained Go checksums.

### Validation summary

Local verification recorded on 2026-10-23 included:

- Linux C++: Debug 102/102, Release 103/103 and probes 102/102 passed. ASan/UBSan passed 97/98; `cpp_native` timed out, then passed a separate diagnostic run without sanitizer findings. The original timeout remains recorded.
- TSan: all 98 cases passed across two selections, with the interruption between them retained. This was not one uninterrupted run.
- Linux Go ordinary/Race selections passed. Windows Go passed 122 SDK tests and nine Command tests; the fixture-dependent SDK system case skipped. Windows Go Race was not run.
- Windows C++: 20 SDK tests, three native platform tests and source/installed SDK consumers passed.
- Three-Star recovery and a ten-minute installed-runtime run passed, with local writes at every Star, cross-node subscriptions and replication. Separate ASan/UBSan and TSan recovery runs had no sanitizer diagnostics.
- Twelve short performance samples, selected Python controls, package-document link checks and offline dependency-license preparation passed within their recorded scopes.

Full release qualification remains blocked. Broader Python controls still fail; two admission mutation outcomes remain invalid; scope/identity inputs
and check adapters are incomplete. Formal paired performance and two-hour resource qualification were not completed on the current source. The short
performance and residence observations do not replace them.

These are local observations from recorded source states, not tests of the subsequently built GitHub archive. The [test guide](tests/README.md)
describes reproduction entries and limits. Hosted [CI results](https://github.com/eosforge/astra/actions/workflows/ci.yml) must identify the exact
commit being evaluated; a passing bounded CI selection does not clear the remaining qualification gaps.

The [release workflow](.github/workflows/release.yml) builds with product tests disabled, checks installed linkage and verifies package hashes.
`build-manifest.json` records the actual source commit, toolchain, libc requirement and packaged file inventory. Tags are annotated and unsigned.
Earlier 0.1.0 downloads can contain different source and assets; see [republication compatibility](docs/releases.md#republication-compatibility).
