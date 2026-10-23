# Build from source

[Documentation](README.md) · [Releases](releases.md) · [Contributing](../CONTRIBUTING.md)

## Requirements

| Target | Build requirements |
| --- | --- |
| Star and Pulsar | Linux x86-64, GCC 16.2.0 with the project's C++26 features |
| Comet C++ | C++23; Linux/GCC 16.2.0 or standalone Windows/MSVC 19.51+ |
| Polaris and Astrolabe | Go 1.27.0+; release builds use 1.27.2; Polaris requires CGO and a C compiler |
| Native dependency builds | CMake 3.28+, Python 3.12+, locked local source archives |
| Release packaging | Linux, Git metadata, tar, ldd and the exact toolchain used by the workflow |

The [native lock](../dependencies.lock.json), [SQLite
configuration](../cmake/sqlite.cmake) and two Go modules own dependency versions. Protobuf 36.1.0 and gRPC
1.84.0 are exact C++ requirements. Arbitrary system versions are not interchangeable.

## Reproduce the release pipeline

The [workflow](../.github/workflows/release.yml) is the complete CI recipe, including its immutable GCC
container digest and build-utility installation. A maintainer can run it for an existing root version tag. The nested Go tag does not trigger a second
binary build.

To reproduce its phases manually, use a source checkout at the release tag inside that same Linux container, with Git, CMake, Python, curl and CA
certificates already available. Review and explicitly allow the preparation downloads in your environment before running:

```bash
export RELEASE_TAG=v0.1.0
python3 -B .github/scripts/release.py prepare
python3 -B .github/scripts/release.py build
python3 -B .github/scripts/release.py package
```

`prepare` downloads checksum-pinned Go and SQLite archives, locked native sources and Go modules, then compiles native dependencies. It maps the
container's existing GCC into `build/tools/gcc-16.2.0`; it does not install GCC on the host. Go license preparation acquires the complete module graph
from temporary copies of each module's metadata, preserving maintained `go.mod`/`go.sum` files. Caches and outputs stay under `build/`.

`build` compiles Star, Pulsar, Comet C++ and the two Go services with network acquisition disabled and `BUILD_TESTING=OFF`. `package` installs into
`build/package/`, verifies runtime resolution, includes public docs/notices and writes the three assets under `build/release/`. Packaging requires the
checkout to match the requested Git tag and refuses to overwrite an existing staging directory.

Guides in the source checkout keep relative links. Packaging preserves links between bundled guides and renders references to omitted source files
or directories as URLs for the selected tag; the maintained source documents are unchanged by packaging.

These are build/packaging commands, not product test or deployment commands. Cold dependency compilation takes substantially longer than a build with
the workflow's matching dependency cache.

## Native targets with prepared dependencies

After the preparation above, from the repository root:

```bash
cmake -S . -B build/cmake/manual \
  -DCMAKE_BUILD_TYPE=Release -DBUILD_TESTING=OFF \
  -DCMAKE_C_COMPILER="$PWD/build/tools/gcc-16.2.0/bin/gcc" \
  -DCMAKE_CXX_COMPILER="$PWD/build/tools/gcc-16.2.0/bin/g++" \
  -DCMAKE_PREFIX_PATH="$PWD/build/deps/astra/linux-gcc16/install" \
  -DFETCHCONTENT_FULLY_DISCONNECTED=ON
cmake --build build/cmake/manual --parallel 2 --target star pulsar comet
cmake --install build/cmake/manual --prefix "$PWD/build/install"
```

CMake consumes the prepared SQLite amalgamation under `build/deps/common/downloads/fetchcontent/sqlite/`; it refuses missing or mismatched input
rather than downloading it. The native install does not build or install Go services. Use the release phases for the complete four-service
distribution.

## Go services

Use the root module for Polaris and Astrolabe, with the selected Go binary on PATH, CGO enabled and an existing C compiler. Prepare the module cache
explicitly before going offline:

```bash
GOTOOLCHAIN=local go mod download
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=1 \
  go build -mod=readonly -p 2 -o build/bin/polaris ./polaris
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off CGO_ENABLED=1 \
  go build -mod=readonly -p 2 -o build/bin/astrolabe ./astrolabe
```

`go mod download` is a separate network operation; omit it when a complete matching cache already exists. Setting `GOTOOLCHAIN=local` prevents
automatic Go toolchain downloads. The [Go SDK](../comet/go/README.md) is a separate module and uses its own cache inputs and checksums.

## SDK consumers and tests

See [Comet C++](../comet/cpp/README.md) for standalone builds and `find_package(Comet)`, and [Comet Go](../comet/go/README.md) for `go get` and a
minimal client.

Test suites and fixtures are included in source, but are not run by the release workflow. Review each test entry's requirements before execution; some
exercise listeners, owned processes, persistence and platform-specific behavior. Configure tests separately from the release build and report the
exact profile and source identity. No test result is implied by these instructions.

The [test guide](../tests/README.md) lists component ownership, root and nested-module commands, explicit
dependency-stub preparation and the three-Star harness. Recorded observations and remaining qualification gaps are described in the
[version validation summary](../CHANGELOG.md#validation-summary).
