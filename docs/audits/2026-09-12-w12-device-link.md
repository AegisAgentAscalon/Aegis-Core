# W12: Device Link boundaries and callback safety

> Historical record for the revision named below. See [current status](../STATUS.md).

Device Link already has one public implementation and one memory adapter of each
kind. This pass counts no earlier facade deletion again. Public contracts are now
grouped around identity/bootstrap, registry trust, presence/resources and links.
Configuration, identity codecs, registry codecs/validation, proof validation and
provider ownership have focused files. Handshake establishment, proof evaluation
and transport reachability have separate service files sharing the same owner.

Four ordinary field-copy conversions use explicit Go struct conversions, with
capability slices still copied. Public and persisted record types remain distinct:
ordinary DeviceIdentity/TrustedDevice JSON omits the public key; explicit identity
bundles and registry backups retain public trust keys. Private keys are not part
of those exports. Public snapshot codecs still materialize empty capability
slices while private fingerprint encoding retains historical nil handling.
The duplicated private registry wire declaration and confirmed dead/redundant
helpers are removed. No public types, methods, error identities or schemas change.

Clock callbacks run outside the shared owner mutex. Time-sensitive sections pair
a clock observation with immediate TryLock acquisition. If the owner is busy,
they wait, discard the earlier observation and sample again before retrying.
Cancellation is checked around the clock and after acquisition. This avoids both
callback reentry deadlocks and acceptance using a timestamp from before a long
lock wait. Related batch timestamps use the same acquired observation. Copies
of Service share the same state and mutex.

Transport calls remain outside owner locks. TestLink measures network completion
time separately from committing reachability; it samples fresh time for that
commit and rereads current trust/fingerprint after acquiring the owner. A revoked,
changed-key or canceled completion cannot record a new trusted link. Reachability
still grants no signed proof or application membership. Handshake expiry, replay,
signature validation, trust-transition boundaries and import rollback remain.

Direct MemoryTransport connections now copy sent payloads, handler inputs and
handler replies. A connection mutex protects the last request and closed state
across concurrent Send/Receive/Close. Handlers run outside that mutex and can
reenter a connection. Nil/empty payload shapes, handler errors and closed-state
error precedence remain unchanged. An already captured Receive may finish after
Close; Close does not cancel a host handler already running.

Regression coverage includes original/copied-owner clock reentry, expiry and
cancellation during owner contention, fresh transport completion with changed
trust, direct adapter mutation isolation and concurrent/reentrant connections.
Existing schema-1 fixtures, public key views, inspection without writes, proof
tampering/replay/revocation/retrust and storage fault cases remain enabled.
A separate public probe compares 60 fixed-clock scenarios against reviewed W11,
including identity/backup key rules, capability shapes, fingerprints, legacy
imports and rejected inputs. Full exact-source/export checks and independent
review are recorded in the campaign evidence. Hosted platform/race qualification
remains a final publication gate; no repository push or release is part of W12.
