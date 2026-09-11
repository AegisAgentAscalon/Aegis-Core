Historical W04a draft. See W04_RELIABLE_DELIVERY_CONTRACT.md for the reviewed
and locally implemented W04b contract. Statements below describe W04a.

# W04 reliable delivery design — review draft

Status: W04a implements bounded legacy pages, provider-clock cleanup and local
snapshot preflight. This document proposes W04b; it does not add a public API.
W07 destination-preserving persistence and an API/protocol design review must
pass before W04b implementation. W04 remains incomplete until its failure matrix
passes. The ordinary suite is not proof of durable delivery.

## Implemented compatibility behavior

LocalDevProvider consumes at most 64 envelopes and 1 MiB of encoded JSON per
receive, including array framing, separators, base64 expansion and the trailing
newline. Remaining envelopes stay queued. Send rejects an envelope that cannot
fit a page before enqueueing it. HTTP receive uses the same byte/count ceilings;
other HTTP endpoints keep their existing limits. Clients drain multiple pages
until empty when they need the whole queue. Each Profile Sync PullRemote call
processes one page.

Configured per-envelope payload limits still apply independently. Legacy custom
providers must return batches within the documented ceilings. The handler rejects
an oversized custom-provider result but cannot undo a destructive receive. Clients
and servers with mismatched payload limits can likewise lose a consumed legacy
batch. These are reasons to require v2, not claims of reliability for v1.

Endpoint/rendezvous query Now is an as-of filter only. Cleanup uses provider time,
including cleanup of mailboxes, envelopes and replay records. Past queries do not
resurrect records expired at provider time. Local snapshot read failure occurs
before Profile Sync consumes the transport queue. Remote inventory reads, trust
checks and writes still occur after receive; none establishes durable acceptance.

## Proposed additive API and wire contract

Keep RelayProvider.ReceiveEnvelopes and SyncTransport unchanged and explicitly
at-most-once. Do not implement v2 by adapting destructive Receive. Require explicit
opt-in capability detection; unsupported providers return a fixed unsupported
result before consuming anything. LocalDevProvider remains an in-memory test
provider and cannot advertise restart durability.

Proposed separate ReliableRelayProvider methods (names subject to review):

- ReceiveBatch(ctx, ReceiveBatchRequest) -> ReceiveBatchResult
- AcknowledgeBatch(ctx, AcknowledgeBatchRequest) -> AcknowledgeBatchResult

Receive request fields: protocol_version=2, namespace, mailbox_id, mailbox_epoch,
max_items and max_encoded_bytes. Defaults and hard caps: 64 items, 1 MiB. Limits
include every wrapper, receipt and escaped field; a single item must fit the
negotiated supported minimum before Send can accept it. Reject unsupported
limits before state mutation. A page is a stable FIFO prefix of currently pending
items; no offset cursor skips unacknowledged items. Empty means no current pending
items, not permanent completion.

Receive result fields: protocol_version, namespace, mailbox_id, mailbox_epoch,
items and has_more. Each item carries an immutable receipt_id and an envelope.
The server persists an unpredictable receipt ID bound to the exact mailbox epoch,
logical message identity and envelope digest at initial acceptance. Redelivery
retains that receipt ID. Receiving never deletes, acknowledges or implicitly
extends authority. Concurrent receives may return the same item; inbox deduplication
handles this without relying on leases. Fair scheduling across mailboxes is a
provider responsibility; poison items must be durably quarantined individually.

Ack request repeats version, namespace, mailbox ID/epoch and a bounded list of
receipt IDs. Ack result gives one fixed status per receipt: acknowledged,
already_acknowledged, unknown, or conflict. Validate authentication, owner/access
policy, request size and mailbox epoch before mutation. A receipt is not a bearer
credential. Unknown IDs never delete another record. Partial success is explicit;
retries of successfully committed acknowledgements are harmless.

Proposed HTTP routes: POST /v2/mailboxes/receive and /v2/mailboxes/ack. Enforce byte
limits on actual encoded requests and responses, not raw payload sizes. Require
complete JSON framing/version checks. A truncated or malformed whole response
causes retry with no acknowledgement. Existing /envelopes/receive remains v1;
never silently downgrade a reliable client. Existing route-wide authorization
alone is insufficient unless the app also authorizes the mailbox/epoch/principal
relationship. This review must settle that authorization contract.

## Durable custody and replay

The reliable provider must durably persist envelope, receipt, mailbox epoch and
replay identity before reporting Send accepted. A memory-only provider cannot
satisfy restart guarantees. Pending items survive provider restart and remain
retrievable until durable acknowledgement; quotas reject new sends before
acceptance. Expiry must produce an explicit durable terminal outcome under a
reviewed retention policy, never silently remove accepted unacknowledged data.
Mailbox recreation gets a new persisted epoch so old receipts cannot affect it.

The application owns a versioned inbox using W07 primitives and domain-local
validation. Receipt identity is provider + namespace + mailbox epoch + receipt ID;
storage keys are domain-separated hashes, preserving exact component boundaries.
Persist the received envelope and its digest before acknowledgement. Repeated
receipt/same digest is a no-op; repeated receipt/different digest is a blocking
conflict, never an overwrite. Store capacity failure leaves the item unacknowledged.

Processing states: pending -> applied or rejected. Persist ingress first, then
acknowledge the provider, then process pending inbox records. A crash after ingress
but before ack causes harmless redelivery; after ack but before application,
startup replays the local inbox. Domain writes must atomically commit their effect
and idempotency identity, or use an equivalent recoverable transaction. A separate
'applied' flag after an ordinary write is insufficient: that crash window can
apply metadata twice. Existing SaveRemoteSnapshot/Proposal interfaces do not
provide this guarantee; design an additive transactional inbox/application seam.

Validate items individually. For malformed domain payloads with valid provider
receipts, persist bounded rejection evidence (receipt identity, digest, fixed
reason code) before ack. Do not persist secrets or arbitrary raw errors in public
diagnostics. Keep valid peers processing independently. Whole-page protocol
corruption is retried without any ack. An invalid/untrusted receipt cannot be
acknowledged; expose a bounded blocking status and retain server custody.

Ack state and applied/rejected tombstones need a coordinated replay horizon.
Pruning them must not allow the same logical accepted message to apply again.
Define explicit storage quotas, retention and administrative recovery before
claiming production support. Retry uses bounded backoff and caller cancellation;
retry exhaustion changes availability status, not custody or acknowledgement.

## Required fault matrix and implementation order

1. Review API/wire versioning, mailbox authorization, custody/expiry semantics,
   inbox transaction ownership and replay/retention policy. Resolve these in a
   concrete contract before implementing exported interfaces.
2. Complete W07 persistence primitives and fault tests, then implement a persistent
   provider spool and inbox with schema recovery. Prove no ack precedes durable
   ingress and no accepted send precedes durable provider persistence.
3. Implement v2 provider/HTTP client/handler and explicit Profile Sync adoption.
   Keep legacy consumers operational with documented at-most-once behavior.
4. Test two maximum-size items, byte and count boundaries, escaped metadata,
   high-count queues and an item that cannot fit. Include exact-limit framing.
5. Inject every local/provider read, write, flush, close and replacement failure;
   disconnect/truncate responses and fail ack writes/responses at each boundary.
6. Restart both processes after acceptance, receive, inbox commit, ack commit,
   domain write and applied-state commit. Verify exact custody, stable receipts,
   idempotent application, mailbox-epoch isolation and preserved originals.
7. Mix malformed and valid peers, conflicting receipt/digest pairs, duplicates,
   concurrent pulls, full inbox/provider quotas, cancellation and expiry. Valid
   accepted items must remain durably held or retrievable; never infer success
   from an aggregate count that hides a missing message.

Acceptance requires the new path to satisfy the entire W04 matrix. W04a closes
SD-04 and two narrow SD-02/SD-03 reproductions; response-failure loss and post-receive
store-failure loss remain live tagged regressions. Fifteen audit findings remain
open. No durable-delivery, hosted qualification or production-ready claim follows
from this draft or the local legacy tests.
