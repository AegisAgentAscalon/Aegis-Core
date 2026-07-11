# Live-main hardening reconciliation — 2026-07-11

Status: draft engineering hardening review

This branch reconciles a July 2026 internal Aegis Core audit with the current public repository. The audited correction was produced from an older embedded lineage, so the correction is being replayed as a security delta rather than copied over the repository.

## Authoritative baseline

- Repository: `AegisAgentAscalon/Aegis-Core`
- Base branch: `main`
- Baseline commit: `667746197a933dc6cdbfe14ccc2feacfb24fd12f`
- Module path retained: `github.com/AegisAgentAscalon/aegis-core`

## Preserved current work

The reconciliation preserves the public module-path migration, Identity Gate foundation, explicit relay authorization/local-development opt-in, constant-time bearer comparison, finite default relay timeout, mandatory SHA-256 artifact verification, and newer OAuth validation.

## Hardening scope

The code delta covers update cache/source/path confinement, requested-version apply behavior, configuration synchronization, strict persisted/HTTP JSON handling, URL validation, OAuth context and storage safety, Device Link discovery/resource freshness, bounded relay request and duplicate tracking, and cross-platform reserved-name checks.

Separate networking, Profile Sync/relay, and update-package feature proposals are intentionally outside this correction branch.

## Validation target

Before review, the branch must pass:

```text
go test ./...
go vet ./...
go test -race ./internal/...
go test -race ./pkg/...
go mod verify
go mod tidy -diff
```

The work is an internal engineering/security hardening pass. It is not an independent penetration test, professional security audit, or production certification.
