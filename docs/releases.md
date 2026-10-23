# Releases, provenance and compatibility

[Documentation](README.md) · [Build](build.md) · [Changelog](../CHANGELOG.md)

## Distribution

| Asset | Contents |
| --- | --- |
| `astra-0.1.0-linux-x86_64.tar.gz` | Four services, Comet C++ development package, compiler runtimes, public guides and notices |
| `build-manifest.json` | Source commit/tag, compiler/Go/libc versions, installed linkage and SHA256 for every packaged file |
| `SHA256SUMS` | SHA256 of the archive and build manifest |

GitHub's automatic source archives contain the versioned repository; they are separate from the compiled Linux archive. Comet Go is an independent
source module, versioned by `comet/go/v0.1.0`; the whole project uses `v0.1.0`. Both tags identify the same source commit for this release.

The public package contains no deployment credentials, databases, Admin frontend, Planet executable or Moon implementation. Source test fixtures are
intentionally public and must not be reused for deployment.

Repository guides use relative links for local and branch browsing. In binary packages, links between included guides stay relative; references to
omitted source files or directories are rendered as links to the exact release tag. The build manifest hashes the packaged documentation bytes.
Testing source and its guide remain in the source distribution.

## Platform and compatibility

The Linux archive is built in the pinned GCC 16.2.0 Debian 13 container. It supplies matching `libstdc++.so.6` and `libgcc_s.so.1`, but not glibc. The
manifest's libc requirement and Linux x86-64 architecture must match the deployment host. Keep `bin/` and `lib/` together.

The C++ SDK uses C++23. Its installed CMake configuration requires the producing platform and exact compiler version plus Protobuf 36.1.0 and gRPC
1.84.0. The Linux archive is not a Windows SDK binary. A standalone Windows/MSVC source entry exists, with its own matching dependencies.

Go SDK source declares Go 1.27.0 as its minimum; the release pipeline uses Go 1.27.2. See [Comet Go](../comet/go/README.md) for installation.

Before 1.0, APIs and wire/storage formats may change between releases. Upgrade services and SDKs together unless a later release documents another
path. Version numbers do not authorize automatic database migration or rollback. Preserve state and identities before an operator-reviewed upgrade.

## Verification boundary

The [release workflow](../.github/workflows/release.yml) checks out the tag, prepares locked inputs,
compiles delivered targets offline, installs the package, inspects linkage and calculates hashes. It verifies the build manifest and uploaded assets
before publication.

The pipeline sets `BUILD_TESTING=OFF`. It does not run product test suites, execute deployment examples or start services. Packaging success is not an
all-tests-passed assertion or independent production certification. Internal historical results are not republished as new tests of the release
archive.

The separate [PR/main CI workflow](../.github/workflows/ci.yml) defines Go compilation/unit selections and Python harness controls. It does not
perform full C++ service qualification, three-Star acceptance, Race, sanitizers or residence campaigns. Local checks on 2026-10-23 exercised selected
Go/Python controls and package-document link rendering. Hosted CI results apply only to their recorded commit; check the
[CI runs](https://github.com/eosforge/astra/actions/workflows/ci.yml) against the package manifest. The release workflow does not wait for this separate
CI workflow or the full qualification gate. Publication does not establish a protected-branch configuration or clear the recorded qualification gaps.

The [version validation summary](../CHANGELOG.md#validation-summary) reports the latest recorded local observations, date and
remaining gaps. The [test guide](../tests/README.md) maps the complete delivered-component test source and
explicit entries, including the restored directed fixtures. Raw execution evidence is excluded from both source and binary releases; frozen public
parser/oracle fixtures remain necessary test inputs. Local observations do not qualify a newly compiled archive; packaging provenance and product
qualification remain separate.

The version tags are annotated and unsigned. SHA256 checks establish byte consistency; they are not a publisher signature. Download all three assets
from one release and retain their source commit when reporting issues.

## Republication compatibility

This 0.1.0 publication rebuilds the initial release from revised source, with both version tags identifying the replacement commit. Earlier 0.1.0
downloads may identify a different commit; replace the archive, checksums and manifest together. The [C++ enum migration](../comet/cpp/README.md)
requires rebuilding callers that used the earlier lowercase names.

Recreating a GitHub release does not clear Go module proxies, checksum records or local caches. A previous cached `comet/go@v0.1.0` can remain visible
or conflict with the replacement content; see [Go's module publication rules](https://go.dev/doc/modules/publishing). A repeated version number alone
does not identify matching bytes. Report the exact source commit and preserve checksum errors for investigation rather than disabling verification.

## Licenses

The root [LICENSE](../LICENSE) covers owned code and documentation under MIT. Installed packages also contain `share/astra/LICENSE` and
`share/astra/licenses/` with third-party terms collected from locked native dependencies, Go modules and runtimes. GCC runtime exceptions and upstream
notices remain in force.

Dependencies are identified by the [native lock](../dependencies.lock.json), [server Go
module](../go.mod) and [SDK Go module](../comet/go/go.mod).
Derived distributions must preserve their applicable third-party terms.
