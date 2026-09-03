# Security Policy

Aegis Core is experimental and has completed an internal engineering audit and hardening pass.

Do not treat this repository as production security infrastructure, managed update infrastructure, a managed relay service, or a malware/security product. It provides reusable setup contracts and local-first helpers that require app-owned review before production use.

## Reporting Issues

Until a formal process exists, report security concerns through the GitHub issue tracker after publication. Do not include secrets, private keys, OAuth tokens, raw provider payloads, private profile data, local machine paths, or user data in public issues.

## Current Review Status

See [`docs/audits/2026-07-11-internal-hardening.md`](docs/audits/2026-07-11-internal-hardening.md) and [`docs/audits/2026-07-16-consumer-driven-hardening.md`](docs/audits/2026-07-16-consumer-driven-hardening.md) for scope, findings, validation, and residual release gates.

- Automated Go tests and `go vet` are expected to pass.
- The code completed internal engineering hardening passes on 2026-07-11 and 2026-07-16.
- No independent professional security audit has been completed.
- No penetration test has been completed.

## Consumer Responsibilities

Apps using Aegis Core own their own production security posture, including OAuth credential storage, update signing policy, update apply behavior, relay hosting, TLS, access control, logging, monitoring, conflict review, backup/rollback, and user-facing disclosure.

Strict Auth services can delegate OAuth token and PKCE-session records to the opaque `pkg/secretstore` contract. The host must supply a production adapter with appropriate current-user or machine protection and revisioned compare-and-swap behavior. Aegis Core does not ship DPAPI, Credential Manager, Keychain, libsecret, or encrypted-file implementations. Legacy Auth constructors retain plaintext compatibility and are not a production protected-storage boundary. Device Link private keys still use package-local file storage and remain a release gate for production security claims.

Identity Gate requires an explicit verification provider. Core does not capture or store biometric samples, templates, passkey material, hardware-key credentials, provider payloads, or raw assertion evidence. A provider result is not trusted unless its opaque receipt is bound to the current subject, provider, session, attempt, assertion, security epoch, freshness requirement, and validity window.

For authenticated update sources, applications must keep credentials in an app-owned HTTP transport or cookie jar, use separate signing keys for development and stable lanes, restrict every manifest/artifact/redirect destination, and protect the release pipeline. Do not put tokens, signed query parameters, or credentials in persisted source or manifest URLs. Aegis source/lane isolation is not a substitute for TUF/Sigstore-equivalent metadata, key revocation, build provenance, destination-IP policy, or installer rollback safety.

Do not expose an unauthenticated relay handler outside isolated local/dev tests. Public or shared relay endpoints need an app-owned authorizer, TLS, abuse controls, and operational monitoring.

Use the record-only update service for new integrations. It can reveal freshly rehashed staged bytes and record consumer-reported lifecycle outcomes, but it cannot run installers, extract packages, restart applications, or execute rollback. The older callback apply path remains deprecated compatibility behavior and must be removed in a separately versioned breaking release before Core can claim a strict non-execution API surface.
