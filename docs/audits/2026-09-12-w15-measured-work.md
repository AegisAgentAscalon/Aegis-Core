# W15: measured compatible computation and I/O work

This pass follows reviewed W14 `84c4fa00`. Public imports/APIs and native storage
schemas remain compatible. No deployment, consumer migration or GitHub update is
part of this local pass. The user ended the autonomous campaign at W15; W16-W18
remain pending.

## Changes

- The reliable Sync receiver reuses an inventory owned by one inbox revision,
  updates it after successful CAS, and reloads after conflict. Generic providers
  retain callback-visible inventory, transport readiness and final status reads.
  Proposal issues use deterministic inbox order instead of unspecified temporary
  map iteration. Clock callbacks execute outside the exchange-history mutex.
- Cloud count/find/collect share one validating scan. Count avoids collection and
  sorting; exact tuple keys avoid repeated in-memory identity hashing. Every body
  is still read and checked, including foreign legacy records before filtering.
  Lookup finishes scanning after a match to preserve late corruption/conflicts.
- Updates reuses equal manifests within one encoding and removes a second JSON
  decode used only for reference counts. Canonical transfer cardinality and bounded
  re-encoding remain: independent review exposed both obligations in the old round
  trip. First handoff hashes at final publication; duplicates/rejections still
  freshly verify bytes. Long reads/parsing observe cancellation. Constructor
  sentinel creation no longer briefly acquires the apply execution gate.

## Measurements and limits

Identical W14/W15 local Windows harnesses use three single-operation timing samples
and separate test-only counters. Setup/reset is excluded; caches are warm and host
activity can affect timing. Raw inputs, logs, medians, correction probes and exact
review bindings are retained in the control workspace's W15 evidence.

For 32 pending reliable snapshots, allocated bytes fell about 30% and allocations
about 34%; elapsed time was essentially unchanged in these samples. Cloud scans
of 1,000 objects allocated less across both tested payload sizes and five operations,
but elapsed times showed improvements and regressions. Body reads remain unchanged.

Updates counters at 4 KiB, 1 MiB, 16 MiB and 128 MiB confirm first handoff hashes
one artifact instead of two. Stage with verification still hashes three times and
copies once; restage still hashes twice and copies zero bytes; status and duplicate
handoff each hash once. One shared-manifest encode uses three private digests instead
of six; decode uses five instead of eight. Canonical size admission still performs
bounded encoding. Whole-operation timing/allocations vary; there is no uniform
speedup, smaller encoded-schema or blanket code/disk reduction claim.

## Review and validation

Retained regressions cover callback-inserted metadata, local/transport phase changes,
provider normalization and failed writes, CAS retries, clock reentry, late cloud
corruption/conflicts, same-size tampering, cancellation, held-lock construction and
initial/duplicate/stale-request handoff integrity without authority advancement.
Independent probes also cover canonical transfer collapse and raw-versus-canonical
JSON size expansion. Corrections preserve the earlier rejection behavior.

The exact frozen commit, source/export test identities, compatibility probes,
minimum-compiler/Linux cross-compilation, dependency/vulnerability checks and
detached VargBot results are recorded in the W15 validation receipt. Cross-compilation
is not Linux runtime/race qualification. Hosted checks remain pending. W14's trusted
local cooperating-writer model, migration/rollback restrictions and unbounded
committed-artifact retention still apply; see [State persistence](../STATE_PERSISTENCE.md).
