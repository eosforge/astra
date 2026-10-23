# Benchmarks

The benchmark source is included for reproduction. Measurements are separate from ordinary regression and require an explicit finite workload,
resource budget, existing dependencies and prepared binaries. See the [test guide](../tests/README.md) and [validation
summary](../CHANGELOG.md#validation-summary).

| Inputs | Scope |
| --- | --- |
| `native.cpp`, `almanac.cpp`, `native.json` | In-process Catalog, Ephemeris and Almanac operations |
| `comet.cpp`, `qualification.json` | Three-Star system workload with local writers at every Star |
| `network.json`, `auth.json`, `concurrency.json` | Explicit transport, authentication and concurrency scenarios |
| `restore.cpp`, `store.cpp`, `push.cpp` | Targeted recovery, storage and transport diagnostics |
| `performance.json`, `paired.py`, `compare.py`, `history.py` | Fixed paired policy, bounded physical samples and offline numerical interpretation |
| `baseline/` | Optional Redis comparison; requires a separately provided Redis stack |

With the prepared Linux toolchain/cache, enable benchmark targets explicitly:

```bash
bash build.sh configure --profile release --benchmarks
cmake --build build/cmake/release --parallel 2 --target star_native_bench star_almanac_bench comet_bench
python3 -B bench/run.py --binaries build/cmake/release --cases bench/qualification.json --repeat 3 \
  --output build/results/performance/qualification
```

Network cases additionally need `star`, `pulsar`, `polaris` and `astrolabe` in the binary directory. The runner starts only its owned fixture services,
requires a new output location and cleans up its processes and temporary state. Do not overlap samples with compilation or other workloads.
`paired.py` requires an already delegated Linux cgroup and the policy's native limits; it is not an unbounded convenience runner.

Report the exact toolchain, workload, source/binary hashes, total resources, warmup and sample counts. End-to-end commit/visibility latency includes
SDK, replication and control-plane costs; a single VM is not a cross-machine deployment or production SLA. Keep failed samples and environment
limitations visible. Raw results belong under `build/results/`, not in this directory. Offline comparison helpers interpret supplied observations;
they neither execute a workload nor establish release eligibility.
