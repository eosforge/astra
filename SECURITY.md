# Security

## Reporting

For a suspected vulnerability, check [Security advisories](https://github.com/eosforge/astra/security/advisories) for a private **Report a
vulnerability** option. Use it when available.

If private reporting is unavailable, open a minimal [issue](https://github.com/eosforge/astra/issues) requesting a private contact channel. Do not
include exploitation details, credentials or sensitive data in that public request. Wait for a maintainer-provided private channel before sending
them. No dedicated security email or guaranteed response time is currently advertised.

A useful private report includes the affected version/commit, component, prerequisites, impact and a minimal reproduction with synthetic data. Do not
probe third-party deployments or publish another operator's information.

## Release support

0.1.0 is the initial release and current reporting baseline. There is no separately maintained LTS branch or published security response SLA. Report
against the newest version where possible; this does not require unsafe upgrades or deleting state.

## Deployment responsibilities

- Provision unique TLS keys, infrastructure accounts and application secrets. Source fixtures are public test material.
- Restrict internal listeners and management access. Keep verified TLS and authentication enabled unless an isolated deployment deliberately chooses otherwise.
- Protect Pulsar and Polaris databases, including journals and backups, with operating-system access controls.
- Keep secrets out of command-line arguments, URLs, logs and public issues. Use protected files or the application's secret provider.
- Review [recovery limits](docs/deployment.md#restart-and-recovery) before changing identities or restoring databases.

The release includes SHA256 manifests and unsigned annotated tags. These do not constitute independent signing or production security certification.
See the [verification boundary](docs/releases.md#verification-boundary).
