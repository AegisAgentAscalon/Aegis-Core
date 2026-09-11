# W06 - Immutable status and ordered callbacks

Baseline: W05 `622f412834c627c511476a84ec1edfb947024a6f`.
Scope: AR-01 through AR-04, SD-08, IG-03 through IG-05.

## Owner patches

- AppBridge reads Auth/Update once and derives the DTO and card from that snapshot.
  Sanitizers copy issue/warning slices, Auth scopes and the Update release pointer.
  Unknown/empty security postures are normalized to unknown and never ready.
- Setup State sanitizes the canonical summary before emitting capabilities/issues.
  A warning with Ready=false also blocks overview readiness.
- Memory discovery clones published and returned presence data using its existing
  complete presence clone helper.
- Identity Gate clones profile aliases, topics and metadata on input and output.
  Hold and unknown delivery channels always hold, including unprotected output;
  known channel policies retain their previous routing decisions.

## Audit delivery contract

Events are constructed and enqueued while the state mutex is held. FIFO order is
queue insertion order, including concurrent state transitions. One active caller
invokes the sink outside the state mutex; callbacks are never concurrent.
Reentrant and concurrent operations enqueue and return without waiting for their
own callback. The active caller drains them after the current callback returns.
A caller that starts a drain returns only after that drain is empty. Returned
operation snapshots describe their committed transition, even if a callback
subsequently changes the session. A callback reading CurrentSession sees current
state, not a historical event snapshot.

Delivery retains best-effort semantics: original contexts are passed to Record,
sink errors are ignored, and there are no retries or durable acknowledgements.
A sink panic propagates to its caller and releases drain ownership; remaining
events can drain on a later operation. A permanently blocked sink blocks its
active drainer and allows a pending queue to accumulate. This is not durable
logging or a guarantee of sink acceptance. No background worker is introduced.

## Validation boundary

The original eight findings are covered by ordinary tests, with input/output
mutation isolation, concurrent projection/discovery, a full channel table,
reentrant audited writes, concurrent FIFO delivery and first-read errors.
Existing Ubuntu/Windows test and Linux race CI jobs cover these tests when run.
Exact source/export checks, compatibility probes and consumer results are stored
in the control repository at evidence/aegis-core-w06-20260911.
No public API or persisted schema change; no W07 implementation, hosted CI run,
push, merge, release or Runtime qualification is claimed.
