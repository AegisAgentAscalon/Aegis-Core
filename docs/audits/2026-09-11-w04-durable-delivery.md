# W04b local reliable delivery candidate

> Historical record for the revision named below. See [current status](../STATUS.md).

Based on W07 correction a272031: canceled update checks preserve selected,
downloaded and verified records and artifact bytes. The review regression failed
before correction and passes afterward. Its separate worktree has an 18-check
source/export/consumer receipt in the control repository.

Independent Astra Ultra protocol review approved contract 674c35d before exported
implementation. Relay ca00c33 and inbox 5cf41a3 implement the new path. A bounded
independent implementation review found six issues; all were corrected and the
reviewer verified the corrections at those commits. They concerned quota draining,
reentrant clocks, zero-clock ingress, delayed freshness, conflict review and
stored trust invariants. Design approval is distinct from implementation proof.

## Implementation

- FileReliableMailbox retains accepted messages and stable receipts in a bounded
  W07-backed file. Receive is nondestructive; ack releases payloads while retaining
  replay identity. Reopen preserves the epoch. Exact send retries return the
  original receipt after expiry or at capacity.
- NewReliableRelayHandler provides authorized v2 send, receive and ack routes.
  HTTPRelayClient implements the separate ReliableRelayProvider seam. Encoded
  limits, complete responses and digest/identity/count checks protect custody.
- ReliableInbox and ReliableSyncReceiver provide explicit Profile Sync adoption.
  Ingress precedes ack; metadata and terminal receipt state commit in the same
  file. Domain-ID duplicates compare content. Malformed peers receive fixed
  rejection reasons while valid peers proceed independently.

Inbox read projections are authoritative for this opt-in path. Existing
SyncManager/LocalMetadataStore and legacy relay APIs are unchanged. No consumer
is silently migrated. No new dependency, generic transaction framework, database,
background worker or cross-process coordination is introduced.

## Local proof

Tests cover byte/count/FIFO/exact bounds, two near-limit messages, high-count
queues, HTTP receive truncation/write failure, authorization, send/ack storage
failure, cancellation, replay after expiry, quota reduction, local preflight and
ingress/ack-state/domain faults, lost commit responses, malformed peers, carrier
binding, domain conflicts, concurrent pulls, corruption and reentrant callbacks.
A child exits after ingress and provider ack; the parent recovers exactly one
metadata effect without shared Go memory. Other restart cuts reopen state objects.
W07 fault tests cover write/flush/close/replacement mechanics under both owners.

Final exact-head source/export/consumer checks and API additions are recorded in
control evidence/aegis-core-w04-durable-20260911. The 894 legacy JSON cases and
150 legacy error identities remain; new v2 behavior has dedicated tests.

## Qualification and adoption

This is bounded single-owner process-restart reliability, not proof of power-loss
durability, hostile filesystem resistance or concurrent independent process safety.
Each root has one owning instance; receivers can share an inbox instance. No
automatic pruning: defaults are 1,024 lifetime receipt records and 32 MiB state.
Inbox admission reserves effect space, so capacity can be reached sooner. Full
stores reject new admission while accepted custody can drain. Offline state/epoch
migration needs a separately reviewed operator procedure.

Hosted Windows/Linux and Linux race/runtime qualification remain pending. Legacy
SD-02/SD-03 cases still demonstrate destructive compatibility behavior; existing
consumers must adopt v2 before claiming reliable delivery. SD-05/SD-06 remain W08
work. Local implementation is distinct from complete campaign acceptance, consumer
migration, qualification, push, merge or release.

See ../plans/W04_RELIABLE_DELIVERY_CONTRACT.md and ../RELIABLE_DELIVERY.md.
