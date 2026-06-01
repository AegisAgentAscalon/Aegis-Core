# Generic Consumer Smoke

This example is a small public-API smoke test for a neutral external consumer.
It is not a real app integration and not a production template.

## What It Exercises

- AppBridge setup overview and relay status through `pkg/appbridge`.
- Direct setup aggregation through `pkg/setupstate`.
- Update check, download, verify, stage, staged summary, and app-owned apply-plan shape through `pkg/updates`.
- Relay local/dev mailbox delivery through `pkg/relay`.
- Profile Sync disabled/degraded status and store-only planning through `pkg/profilesync`.
- Cloud-compatible metadata object storage, manifest comparison, and referenced-object verification through `pkg/profilesync`.

## Boundaries

- Imports public `pkg/*` packages only.
- Uses temporary local state only.
- Requires no credentials, no external network, and no long-running service.
- Does not execute update apply behavior.
- Does not add app-specific behavior or a named consumer relationship.
- Does not store private profile data or add app-specific runtime logic.

## Run

```powershell
go test ./examples/generic-consumer-smoke
go run ./examples/generic-consumer-smoke
```
