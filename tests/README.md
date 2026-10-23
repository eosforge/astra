# Tests

The source distribution includes the delivered components' tests, shared fixtures, fault and mutation definitions, model checks, and benchmark
drivers. Test source is separate from the installed binary package. The [0.1.0 validation summary](../CHANGELOG.md#validation-summary) records
recorded observations and their limits; including a test does not mean it has passed every supported configuration or the downloaded release archive.

## Source map

| Scope | Source and entry |
| --- | --- |
| Common configuration, clock, storage, allocation and protocol boundaries | [common/tests](../common/tests), root CMake/CTest |
| Star state, replication, snapshots, pagination, recovery and resource limits | [star/tests](../star/tests), root CMake/CTest |
| Pulsar admission, clock, SQLite durability, allocation and RPC faults | [pulsar/tests](../pulsar/tests), root CMake/CTest |
| Comet C++ lifecycle, publication, subscription and public consumers | [comet/cpp/tests](../comet/cpp/tests), root or standalone SDK CMake/CTest |
| Comet Go local units, examples, fuzz seeds and system consumers | `*_test.go` in [comet/go](../comet/go); this is a separate Go module |
| Polaris, Astrolabe, shared admission and command handling | Colocated `*_test.go` in [polaris](../polaris), [astrolabe](../astrolabe) and [internal](../internal) |
| Cross-process, installed-package and three-Star scenarios | [test_pulsar.py](test_pulsar.py), [test_comet_process.py](test_comet_process.py), [test_comet_package.py](test_comet_package.py), [soak.py](soak.py) |
| Harness, model, coverage and evidence-reader controls | `test_*.py` here, with native helper tests colocated under [tools](../tools) |
| Performance and optional comparison workloads | [bench](../bench/README.md) |
| Public identities, fault templates and fixed parser inputs | [fixtures](fixtures/README.md) |

Admin and Planet implementation tests are outside the delivered scope. Role values and public negative-test identities bearing those names remain
protocol fixtures; they do not add a product executable.

## Prerequisites and ordinary checks

Use the [build guide](../docs/build.md) to prepare the exact compiler and dependency inputs. Commands below use existing local tools and caches;
they do not install dependencies. Run only in an authorized, isolated environment. Choose build and test parallelism within one measured resource
budget. Tests can open loopback listeners, create temporary databases and start their own short-lived processes.

For the Linux service/C++ regression, the unified entry expects the documented project cache layout or an explicit `ASTRA_CACHE_ROOT`:

```bash
bash build.sh regression --profile release --jobs 2 --test-jobs 1
```

This runs the root Go service selections, CTest and generated-source comparison. It does not discover the nested Comet Go module. Core-only
`bash build.sh test --core-only` is a smaller configuration/state selection, not full service acceptance. Sanitizers, coverage, continuous fuzzing,
benchmarks and long residence have separate explicit profiles; they are not implied by ordinary regression.

With Go 1.27.2, a prepared module cache and an existing C compiler where CGO is needed:

```bash
export GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOMAXPROCS=4
go test -mod=readonly -count=1 -p=1 -parallel=1 -timeout=180s ./internal/... ./polaris/... ./astrolabe/...
go -C comet/go test -mod=readonly -count=1 -p=1 -parallel=1 -timeout=180s ./...
```

If dependencies were prepared in the project cache, set `GOMODCACHE` to that existing `build/deps/go/pkg/mod` directory. An unavailable dependency
must fail offline. Linux Race is a separate selection: add `-race` only when explicitly intended, with CGO and a compatible compiler available.
System SDK cases requiring an external harness can skip in an ordinary package run; report those skips rather than calling them system passes.

For Python harness controls without native child tools, use an explicit module such as `python3 -B -m unittest tests.test_pulsar_harness -v`.
The separate `tests.test_build` suite requires existing CMake 3.28+ and CTest. It invokes configure, empty-build and test phases against language-free
fixtures; it does not compile Astra product code. Include those child tools in the chosen execution scope.
Broad unittest discovery is not a substitute for selecting a supported profile: some entries require native artifacts or separately retained
evidence. `development.json` and the historical qualification readers retain the wider development policy, including excluded components and
internal design references. They are not a standalone public-release certification command. Missing evidence must remain missing.

## Pull-request baseline

The [CI workflow](../.github/workflows/ci.yml) defines two bounded Ubuntu jobs for pull requests targeting `main`, pushes to `main` and manual runs:

- Python: `tests.test_build`, `tests.test_pulsar_harness`, `tests.test_benchmark` and `tests.test_release`. The build-entry controls use existing
  language-free CMake/CTest fixtures; release controls use miniature source trees and an existing Go toolchain with a local file proxy, without external
  module downloads or building/publishing a product package.
- Go: exact Go 1.27.2 setup and explicit module preparation, followed by offline compilation and ordinary unit selections in the root and Comet Go
  modules. Parallelism is two packages, with one parallel test per package and a 180-second package limit. JSONL artifacts preserve actual results,
  failures and skips; the opt-in SDK system case remains outside this local selection.

Go setup may acquire the exact toolchain and `go mod download` fetches the selected dependencies in each module in the isolated CI runner.
The Python job uses tools already supplied by the runner. Jobs have 10/15-minute outer limits. Full native C++/service checks, Linux Race,
sanitizers, explicit login/clock models, three-Star acceptance, fuzz campaigns, benchmarks and residence remain separate selections.
Selected local Go/Python and package-document controls ran on 2026-10-23. Hosted workflow results are separate and apply only to their recorded commit;
inspect the [CI runs](https://github.com/eosforge/astra/actions/workflows/ci.yml) for that identity.

## Restored directed cases

The following source was recovered from the retained, successful experiments without changing product logic or weakening assertions:

- `comet/go/isolated*_test.go`: local admission, ownership, cancellation, RPC and Windows clock-failure cases. The Linux clock fixture below needs
  its dependency model and is deliberately outside ordinary Go discovery.
- [comet/cpp/tests/draining_test.cpp](../comet/cpp/tests/draining_test.cpp): all five real Core resource claims prevent completed shutdown until
  their matching return. Registered as `cpp_comet_draining`, with a 30-second CTest limit.
- [pulsar/tests/commit_test.cpp](../pulsar/tests/commit_test.cpp): a real SQLite sync refusal cannot publish registration success, and the same
  database can be reopened for a subsequent successful registration. Registered as `cpp_pulsar_commit`, with a 120-second CTest limit.

With the prepared toolchain/cache, configure a test build and select the two new C++ entries:

```bash
bash build.sh configure --profile release --jobs 2 --test-jobs 1
cmake --build build/cmake/release --parallel 2 --target comet_draining_test pulsar_commit_test
ctest --test-dir build/cmake/release --output-on-failure --no-tests=error --parallel 1 \
  -R '^(cpp_comet_draining|cpp_pulsar_commit)$'
```

The configure entry explicitly re-enables `BUILD_TESTING`, including when this directory was previously configured for release packaging with tests
disabled. The root build registers both directed targets; standalone SDK builds select the drain fixture with `COMET_BUILD_TESTS=ON`.

The registered C++ cases ran in the 2026-10-23 native selections summarized in the changelog. The explicit login and Linux clock preparation/model
commands below were not rerun by that campaign; their historical executions retain their original isolated inputs and recipes.

### Login dependency model

[comet.py](comet.py) prepares a fresh source copy under ignored `build/`; it does not run Go or start processes. The login profile verifies the exact
original `connection.go` hash and substitutes only transport construction, readiness and Session dispatch. It preserves the control flow and all
confirmation/cancellation guards. Tests forbid dialing and restore their process-local callbacks.

```bash
python3 -B tests/comet.py login --output build/tests/login
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOMAXPROCS=4 \
  go -C build/tests/login/module test -mod=readonly -count=1 -p=1 -parallel=1 -timeout=180s -run '^TestLoginBoundary' .
```

For the separately authorized Linux Race selection, add `-race` to that Go command. Use the same prepared dependency cache as ordinary SDK tests.
Never count these stub observations as coverage of the unmodified concrete gRPC constructor or all real-network schedules.

### Linux clock dependency model

The clock profile needs an existing `golang.org/x/sys v0.48.0` directory. It validates the recorded syscall-source digest, copies the dependency
locally with its license, and injects only the BOOTTIME fixture. It changes neither the dependency cache nor the machine clock. Run on Linux:

```bash
python3 -B tests/comet.py clock --output build/tests/clock \
  --sys-module "$PWD/build/deps/go/pkg/mod/golang.org/x/sys@v0.48.0"
GOTOOLCHAIN=local GOPROXY=off GOSUMDB=off GOWORK=off GOMAXPROCS=4 \
  go -C build/tests/clock/module test -mod=readonly -count=1 -p=1 -parallel=1 -timeout=180s \
  -run '^TestIsolated(ClockFailure|RestoreClock)$' .
```

Preparation refuses an existing output directory. Review and retain previous outputs before choosing a fresh location. The commands bound Go test
duration and scheduling; enforce any required CPU/memory limits on the entire process tree in the surrounding job or cgroup. Synthetic timestamps
verify rejection arithmetic and recovery behavior, not observed kernel accuracy or actual suspend/resume.

## Three-Star integration and residence

The maintained [soak runner](soak.py) owns Pulsar, Polaris, Astrolabe and three Stars. Each Star accepts local writes; the SDK verifies cross-node
views, bidirectional replication and recovery. It consumes already built artifacts and never builds or downloads them. Prepare the C++ process/mesh
probes and the Go SDK system test executable separately. A finite combined control uses:

```bash
python3 -B tests/soak.py --binaries build/cmake/release --comet-go build/bin/comet-go-system \
  --output build/results/system-control --persistent --fault-seconds 0 --steady-seconds 0 --interval 0 --records 16
```

The system executable is produced separately with `go -C comet/go test -c -mod=readonly -o "$PWD/build/bin/comet-go-system" .`, using the offline
environment above and the agreed toolchain. The runner requires Linux `/proc`, qualified
physical time, isolated ports/data and explicit host limits. `--installed` selects installed-runtime checks. Long residence, including the dedicated
`--comet-go-residence` mode, needs its own duration/resource budget. The obsolete `build.sh soak` alias is rejected; use the maintained runner.

## Results and publication

Keep raw logs, profiles, native archives, binaries and process records under ignored `build/results/` or an external CI artifact store. Publish only
the version-specific summary and available CI links. Public `.cover`, JSON and `.go.in` fixtures are required reader/oracle inputs, not fresh test
results. They do not qualify a release without the corresponding native evidence and source binding.

The source additions above retain the original experiment boundaries. Login and clock models remain explicit; failed intermediate Pulsar fixtures
and historical acquisition/collector scripts are not copied. Historical results are not rerun or relabeled by this source restoration.
