# Consumer migration and rollback

This is a migration guide, not evidence that a consumer was installed or upgraded.
The campaign preserves public `pkg/` imports and validates one detached VargBot
revision against the candidate through an alternate modfile. That proves only the
recorded compile/focused checks for that source. Authoritative consumer manifests
remain unchanged; every real application must qualify its own integration.

## Source integration

Pin an explicitly reviewed published commit or authorized tag. Check `go list -m
-json github.com/AegisAgentAscalon/aegis-core` from the consumer module and record
the resolved version/replacement. Run that application's compile, integration and
behavior checks; a test against its old pinned Core does not qualify the candidate.
W17 removes no public symbols. AppBridge, Setup State, legacy Updates constructors
and aliases continue to exist under the same imports.

## Persistent state

[State persistence](STATE_PERSISTENCE.md) is the authority for native Profile Mesh
and Updates migration, locks, recovery and retention. Before deployment:

1. Stop all old writers, including background services, and take an offline backup
   of the complete affected roots and required artifact files. Keep the original
   executable and its configuration with that backup.
2. Qualify migration on an isolated copy using the intended OS/filesystem and
   consumer. Exercise interruption, reopen, cancellation and stale-writer behavior.
   Confirm bounded invalid state fails safely; do not repair it by deleting native
   authority or accepting a regenerated fixture.
3. Start only cooperating new-format writers against production roots. The first
   successful mutation activates `state-v2`; frozen legacy files cease to be live
   authority. Reads must not promote backups or old generations after corruption.
4. Do not downgrade an executable against a migrated root. A rollback requires
   stopping all writers and restoring a separately verified complete pre-migration
   backup into an isolated root. This discards later mutations and is a host-owned
   recovery operation, not an automatic Core rollback feature.

Do not delete lock sentinels to resolve contention. Native generations cover the
documented trusted-local/cooperating-process model, not hostile replacements,
power-loss ordering or network filesystems. Updates retains committed artifacts:
Clear revokes current authority but does not erase bytes or revoke disclosed paths.
Plan disk retention and offline recovery separately.

## Protocol and authority integration

Legacy Profile Sync exchange keeps its disclosed SD-02/SD-03 delivery limitations.
Adopt the reliable v2 sender, custody and inbox contracts explicitly, following
[Reliable delivery](RELIABLE_DELIVERY.md). Provision host-owned stores/trust and
test retries, duplicate delivery, restart, cancellation and partial failure before
switching consumer traffic. Reliable inbox custody does not automatically copy
effects into the consumer's legacy metadata store.

For new Updates integrations, use the record-only lifecycle and consumer-owned
installation. Core records handoff and reported outcomes; it does not acquire
installer authority. Retained legacy callbacks do not provide exactly-once external
execution. Preserve signature/source policy and fresh artifact checks in either
path; method aliases are not a reason to bypass admission checks.

Strict Auth requires a qualified host-owned protected store with its revision/CAS
contract. Development memory adapters are not production protection. Identity Gate
requires explicit verification authority; do not regain old permissive behavior by
installing a mock provider in production. Consumer-specific provider qualification,
security review and user-visible recovery handling remain necessary.
