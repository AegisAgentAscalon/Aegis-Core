# Security Policy

Aegis Core is experimental and has completed an internal engineering audit and hardening pass.

Do not treat this repository as production security infrastructure, managed update infrastructure, a managed relay service, or a malware/security product. It provides reusable setup contracts and local-first helpers that require app-owned review before production use.

## Reporting Issues

Until a formal process exists, report security concerns through the GitHub issue tracker after publication. Do not include secrets, private keys, OAuth tokens, raw provider payloads, private profile data, local machine paths, or user data in public issues.

## Current Review Status

See [`docs/audits/2026-07-11-internal-hardening.md`](docs/audits/2026-07-11-internal-hardening.md) for scope, findings, validation, and residual release gates.

- Automated Go tests and `go vet` are expected to pass.
- The code completed an internal engineering audit and hardening pass on 2026-07-11.
- No independent professional security audit has been completed.
- No penetration test has been completed.

## Consumer Responsibilities

Apps using Aegis Core own their own production security posture, including OAuth credential storage, update signing policy, update apply behavior, relay hosting, TLS, access control, logging, monitoring, conflict review, backup/rollback, and user-facing disclosure.

For authenticated update sources, applications must keep credentials in an app-owned HTTP transport or cookie jar, use separate signing keys for development and stable lanes, restrict every manifest/artifact/redirect destination, and protect the release pipeline. Do not put tokens, signed query parameters, or credentials in persisted source or manifest URLs. Aegis source/lane isolation is not a substitute for TUF/Sigstore-equivalent metadata, key revocation, build provenance, destination-IP policy, or installer rollback safety.

Do not expose an unauthenticated relay handler outside isolated local/dev tests. Public or shared relay endpoints need an app-owned authorizer, TLS, abuse controls, and operational monitoring.
