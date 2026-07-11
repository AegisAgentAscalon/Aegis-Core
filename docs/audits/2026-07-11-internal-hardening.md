# 2026-07-11 Internal Audit and Live-Repository Hardening

## Status

This document records an **internal engineering review and hardening pass**. It is not an independent professional security audit, penetration test, certification, or production-readiness guarantee.

The original review targeted the archived Aegis Core 035 source under its earlier module identity. The fixes were then reconciled onto the public repository at base commit `667746197a933dc6cdbfe14ccc2feacfb24fd12f`, whose module path is:

```text
github.com/AegisAgentAscalon/aegis-core
```

The public repository already contained newer Identity Gate work and several independent safeguards. The reconciliation used a three-way merge, retained those newer changes, preserved existing public error behavior, and added regression coverage for the remaining findings.

## Result

The review assigned 22 findings: 4 high, 13 medium, and 5 low. The current hardening branch resolves all 22 without adding dependencies or removing public APIs.

| ID | Severity | Resolution in the live repository |
| --- | --- | --- |
| U-01 | High | Withdrawn or newly incompatible updates clear cached candidate/download state. |
| U-02 | High | Persisted selections and downloads carry a normalized source binding and are revalidated. |
| U-03 | High | Persisted artifact paths must resolve to package-owned regular files. |
| U-04 | High | Remote manifest providers cannot select local-path or `file:` artifacts. |
| U-05 | Medium | `Apply(ctx, version)` rejects a version other than the staged version. |
| U-06 | Medium | Mutable update configuration and workflow state use one synchronization boundary; app callbacks run outside the lock. |
| U-07 | Medium | Manifest verification-key maps are cloned at service construction. |
| U-08 | Medium | Persisted selected/downloaded/verified/staged wrappers receive strict schema, source, timestamp, and artifact validation. |
| U-09 | Low | Release-note, provider, and artifact URLs stay inside their intended web/local trust boundaries. |
| U-10 | Medium | Numeric version components are compared without machine-integer overflow. |
| U-11 | Low | Negative artifact-size policy values are rejected. |
| U-12 | Low | Staging honors cancellation, replacement rejects unsafe targets, and cleanup failures propagate. |
| A-01 | Medium | Selected Auth, Update, Device Link, and relay paths normalize nil contexts before context-dependent operations. |
| A-02 | Medium | Private state directories are repaired to mode `0700` where supported and final symlink components are rejected. |
| D-01 | Medium | Device Link provider callbacks execute outside the service mutex and returned presence data is cloned. |
| D-02 | Medium | Remote resources are available only for fresh, fingerprint-matching, trusted peers. |
| D-03 | Medium | Implausibly future-dated presence is treated as stale in Device Link and Profile Mesh. |
| R-01 | Medium | Relay duplicate-delivery records expire with their envelope lifetime. |
| R-02 | Medium | Relay base URLs require HTTP(S), a host, and no user info, query, or fragment; the default client timeout is finite. |
| R-03 | Medium | Relay requests and responses use bounded, strict, single-document JSON decoding. |
| R-04 | Low | Static bearer comparison is constant-time and local relay status is nil-context safe. |
| X-01 | Low | Safe-name checks reject Windows device names even when followed by an extension. |

Some safeguards were already present on public `main`, including version-aware apply behavior, the remote/local artifact boundary, a finite default relay timeout, constant-time bearer comparison, explicit relay authorization opt-in, and nil-safe local relay status. The hardening branch preserves those implementations and fills the remaining gaps instead of replacing the public tree with the archived correction ZIP.

## Validation performed on the reconciled tree

The following checks passed locally against the exact pull-request head:

```text
git diff --check
go test ./...
go vet ./...
go test -race ./internal/...
go test -race ./pkg/...
go mod verify
go mod tidy   # no go.mod or go.sum change
```

Pull-request CI also runs module verification, ordinary tests, race tests, and vet.

## Residual release gates

The corrections above remove concrete defects; they do not turn every reference component into a production security system. The principal remaining gates are:

1. Independent artifact authorization, key rotation/revocation, and delegated/expiring update metadata before unattended update apply.
2. Redirect and destination policy before accepting untrusted update endpoints.
3. OS-backed keystore adapters for high-value identity material.
4. Journaled or transactional persistence for multi-file workflows.
5. Authenticated snapshot signatures with epoch, freshness, rollback, and revocation checks.
6. A hardened relay deployment wrapper with TLS, server timeouts, rate limiting, replay controls, monitoring, and abuse controls.
7. Profile Mesh referential-integrity validation and repair tooling.
8. A repository-wide decision on whether nil `context.Context` is supported or rejected.
9. CI coverage for the repository's PowerShell checks and optional analyzers such as `govulncheck`, `staticcheck`, and a selected security analyzer.

See [`../ROADMAP.md`](../ROADMAP.md) for ownership and priority.
