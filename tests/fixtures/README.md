# Public test fixtures

These files are deliberately public test inputs. Certificates, private keys, account passwords and admission-signing keys are isolated test
identities, never deployment credentials. Trust their CA only in a test process; do not install it into the system trust store.

| Inputs | Purpose |
| --- | --- |
| `pulsar/`, `star-a/` through `star-d/` | Admission, TLS, replication and recovery identities |
| `wrong-cluster/`, `expired/`, `rogue/`, `untrusted/` | Authentication and trust rejection cases |
| `planet-a/`, `planet-b/` | Reserved protocol role/identity fixtures, not a shipped Planet service |
| `admission-v1.json`, `admission-v5.json` | Fixed encoding and identity vectors |
| `*.json`, `*.cover`, `*.go.in` | Model/oracle inputs, frozen parser examples and explicit fault instrumentation |
| `comet/` | Login dependency seams and Linux BOOTTIME models prepared by [comet.py](../comet.py) |

Historical path strings and hashes in parser fixtures describe their original inputs. They are not paths to create, commands to execute, current
coverage results or secrets. Keep valid and invalid cases together. Source fixtures remain versioned even when their format resembles a report;
actual campaign logs, coverage exports and archives stay outside the source distribution.

The restored Comet templates preserve the original local stubs. `login.go.in` and `login_test.go.in` are materialized only in the login profile.
`clock_linux_test.go.in` requires the matching `clock_linux.go.in` dependency model and must not be renamed into ordinary package discovery.
The Windows clock case uses the already available Windows API adapter and is selected by its `_windows_test.go` suffix.

Fixture renewal is explicit. [generate_fixtures.py](../../tools/generate_fixtures.py) requires an existing Python/cryptography environment; do not
download dependencies, replace identity bytes, regenerate certificates or change host time as a side effect of running tests. Temporary databases,
copied inputs and generated dependency trees belong under ignored `build/`.

See the [test guide](../README.md) for execution boundaries and the [validation summary](../../CHANGELOG.md#validation-summary) for historical results.
