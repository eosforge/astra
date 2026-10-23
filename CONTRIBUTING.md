# Contributing to Astra

Start with the [documentation](docs/README.md), [build guide](docs/build.md) and
[test guide](tests/README.md).

Participating in project spaces means following the [Code of Conduct](CODE_OF_CONDUCT.md).

## Issues and proposals

Use [GitHub Issues](https://github.com/eosforge/astra/issues) for reproducible bugs and focused proposals. Include the component, version/commit,
operating system/toolchain, minimal reproduction, expected result and actual result. Redact credentials, cookies, keys and application payloads.
Follow [SECURITY](SECURITY.md) for suspected vulnerabilities.

Discuss new features, public API changes, storage migrations and broad refactors before implementing them. The 0.1.0 scope is intentionally bounded; a
small change tied to a concrete problem is easier to review.

## Pull requests

1. Make a focused branch from current public source.
2. Preserve public contracts and explain changes to failure, concurrency, persistence or compatibility behavior.
3. Update the relevant component/SDK guide and changelog for user-visible changes.
4. Run appropriate checks in your own authorized environment. State exact commands, toolchain and results; list checks not run.
5. Submit a pull request describing the problem, resulting behavior and validation. Exclude build outputs, caches, real credentials and local evidence archives.

Dependency preparation is an explicit network step. Ordinary builds and tests must not silently fetch tools or dependencies. Edit protocols through
their `.proto` source and pinned generator entry, not generated files by hand.

The [CI workflow](.github/workflows/ci.yml) defines bounded Linux Go compilation/unit selections and Python harness checks for pull requests and
`main`. Go setup and module acquisition are explicit preparation steps; compilation and Go tests run offline. C++ runtime qualification, Race,
sanitizers and three-Star acceptance use the separate entries in the test guide. Include any required checks outside this CI selection in your PR's
validation record. A successful baseline CI result covers only its named selections.

## Code conventions

Use `.editorconfig`, `.clang-format`, module files and `pyproject.toml`. C++ uses `.hpp`/`.cpp`, explicit ownership and checked results; Go uses
`gofmt`; Python uses the configured Black style. Format changed files and preserve third-party/generated code.

Keep callbacks outside internal locks, bound queues and cleanup, and distinguish a failed response from an uncommitted operation. Regression cases
should demonstrate the contract failure rather than mirror implementation. A format check or compile-only run is not a behavioral test.

## Release changes

Maintainers publish version tags using the [release workflow](.github/workflows/release.yml). Root and
nested Go module tags have different names; see [releases](docs/releases.md). A pull request does not itself authorize publication or credential use.

Owned contributions are distributed under the [MIT License](LICENSE). Preserve upstream notices and identify proposed third-party material's origin
and license. Keep discussions respectful, specific and focused on the work.
