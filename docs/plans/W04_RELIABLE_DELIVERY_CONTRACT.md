# W04b implementation contract

Status: independently reviewed at 674c35d before exported implementation;
implemented locally by ca00c33 and 5cf41a3, with qualification still pending.
Supersedes the proposed choices in W04_RELIABLE_DELIVERY_DESIGN.md; the historical
W04a behavior and limitations in that document remain accurate.

## Scope and custody

Add an explicit reliable path. Existing RelayProvider, SyncTransport, constructors,
wire schemas and destructive Receive remain unchanged. Neither LocalDevProvider
nor a legacy adapter may advertise reliable custody. No silent downgrade.

The guarantee concerns acknowledged filesystem commits and process restart under
W07's trusted, single-writer root contract. It is not a power-loss guarantee or a
cross-process transaction. Parent-directory flush and hosted Linux/Windows/race
qualification remain outside the proven local capability.
One owning provider/inbox instance per state path is required. Multiple receivers
may share that inbox instance; revision checks do not coordinate independently
reopened objects or another process.

Custody transitions are provider spool -> local inbox -> committed metadata or
durable rejection. A receive is read-only. Acknowledge follows persisted ingress.
The metadata effect and terminal receipt state share one file replacement.

## Relay owner and additive API

FileReliableMailbox owns one host-provisioned mailbox and one bounded state file.
Its configuration fixes provider ID, namespace, mailbox ID and owner device ID.
Construction creates and persists a random epoch only for a new state file; reopen
must match the saved identity exactly. Mailbox() exposes its full immutable
ReliableMailboxRef. Provisioning is a trusted host operation, not an HTTP route.
There is no automatic mailbox recreation or epoch rotation in this slice.

ReliableMailboxRef contains provider_id, namespace, mailbox_id, owner_device_id
and epoch. All requests repeat the exact reference and protocol_version=2.
ReliableRelayProvider has three methods:

- SendReliableEnvelope(ReliableSendRequest) -> ReliableSendResult.
- ReceiveBatch(ReceiveBatchRequest) -> ReceiveBatchResult.
- AcknowledgeBatch(AcknowledgeBatchRequest) -> AcknowledgeBatchResult.

Each method accepts context.Context. Send carries a version-1 RelayEnvelope inside
the v2 wrapper; existing envelope encoding is unchanged. Namespace, mailbox and
target device must match the addressed mailbox. The provider validates the
envelope at acceptance, including payload hash, time and supported encoded size.

Send persists a random 256-bit receipt, canonical envelope SHA-256 digest and
logical identity (source device ID, message ID) before reporting acceptance.
The same logical identity and digest returns the same receipt, including after
acknowledgement; a changed digest is a conflict. The caller retries the exact
envelope, including timestamps, after an ambiguous send response.
Canonical digest means lowercase SHA-256 of Go encoding/json.Marshal on the typed
RelayEnvelope, exposed through ReliableEnvelopeDigest and used at every boundary.
It is a Go JSON encoding contract, not a general cross-language canonical JSON
standard. Domain digests use json.Marshal of the typed snapshot or proposal.
Look up accepted logical identity before current-time or quota admission so an
exact retry still succeeds after expiry or at capacity. Reopen validates static
structure and digests, never current-time validity of already accepted records.

Receive returns a stable FIFO prefix of pending entries, stable receipt/digest,
full mailbox identity, version and has_more. It never mutates the spool. Pending
entries do not disappear when their original expiry passes: the receiver retains
custody and may explicitly reject stale data during domain validation.

Receive supports 1..64 items (zero means 64). The only supported byte limit is
1 MiB (zero means 1 MiB). Reject other byte limits before IO; this avoids accepting
an item that a later negotiated smaller page could never deliver. Every encoded
response includes wrapper, base64, metadata, separators and newline in the limit.
Send admission proves a one-item result fits that limit. Requests share the 1 MiB
wire bound. Payloads independently remain bounded by provider configuration.

Ack accepts up to 64 unique receipt IDs. Outcomes are acknowledged,
already_acknowledged, or unknown, in request order. A wrong mailbox identity or
epoch rejects the entire request before mutation. A successful ack commits all
known requested receipts in one snapshot; unknown IDs cannot delete other data.
Keep digest, logical identity and receipt tombstones after releasing payloads.

## Authorization and HTTP

NewReliableRelayHandler serves only POST /v2/envelopes, /v2/mailboxes/receive and
/v2/mailboxes/ack. It requires an authorizer with no unauthenticated bypass.
After bounded strict request decoding and before provider access, the authorizer
receives the HTTP request, action, full mailbox reference and asserted source
device (send only). It must authenticate the request and authorize that principal
for the action/reference/source relationship. A receipt or owner_device_id field
is never itself authority. Denial touches no provider state.

The host resolves credentials and membership; Core never infers identity from
client-supplied fields. The same trust boundary applies to direct provider calls:
only a trusted host may invoke them without the HTTP authorization adapter.
Tests deny cross-owner, cross-namespace, stale-epoch and spoofed-source requests.

HTTPRelayClient gains additive v2 methods with complete bounded response framing
and identity/version/digest/count checks. Unsupported routes fail without a
legacy retry. Handler pre-encodes and bounds responses before writing them.
Disconnects or failed response writes do not remove pending records; lost ack
responses are resolved by idempotent ack retry.

## Profile Sync receiver and inbox

ReliableInbox owns one separate state file bound to the complete mailbox ref.
It stores ingress envelope/digest/receipt/time, ack status, pending/applied/rejected
state, bounded fixed rejection reason and the remote snapshot/proposal maps.
Receipt identity is scoped by the entire persisted mailbox identity, never by a
receipt ID alone. Same receipt/digest is a no-op; changed digest fails closed.

ReliableSyncReceiver is an explicit new consumer. It is configured with provider,
mailbox, inbox, local snapshot reader, clock and trust verifier. PullRemote loads
the local snapshot before receiving, recovers previously pending inbox work, then
receives a bounded page. It persists each ingress before ack; malformed Profile
Sync payloads still have valid provider receipts and are quarantined individually.
Whole-page protocol corruption produces no acknowledgement.
Before any domain effect, the decoded SyncEnvelope namespace/source/message ID
must match its relay carrier, and the carrier target must match the bound mailbox
and owner. A mismatch is a durable fixed-code rejection, not a metadata write.

Ack failures leave local ack intent retryable. Processing can continue for locally
stored items even if the provider is unavailable. A later call retries outstanding
acks; ack-state write failure is harmless because the server remembers tombstones.
Each call performs bounded work, with no internal infinite retry or sleep loop.

Reuse existing Profile Sync header, snapshot/proposal, trust, duplicate and review
classification on a private temporary transaction view. Do not call the legacy
store's SaveRemote methods and then set an applied flag. One inbox snapshot commits
both the classified metadata effect and terminal receipt state; retry cannot
incrementally apply that metadata twice. Preserve the first recorded receive time.
Processing records ProcessedAt separately and evaluates freshness at that time.
Read projections expose historical Freshness.ObservedAt; they do not assert current
availability. Candidate states are validated before replacement, including nonzero
clocks and stored domain/trust/review invariants.
Across distinct receipts, compare canonical domain-content digests for the same
snapshot/proposal ID: exact duplicates have no additional effect; changed content
is an explicit conflict without overwrite. Legacy ID-only duplicate checks alone
are insufficient. Classify outside the inbox data lock, including trust callbacks;
commit only if the saved revision still matches. Revision conflict retries a
bounded number of times or leaves the item pending for the next call.

Inbox ListRemoteSnapshots/ListRemoteProposals are the authoritative projections for
this path. They do not silently write or merge legacy LocalMetadataStore files.
Consumers opt in by constructing the receiver and reading those projections;
legacy SyncManager PullRemote remains explicitly at-most-once. This slice stores
reviewable remote metadata, not automatic application to live profile authority.

## Capacity, corruption and operations

Provider and inbox use bounded whole-state JSON snapshots for a small first
implementation: default 1,024 lifetime receipt records and at most 32 MiB encoded
state. Configurable smaller limits support deployments/tests; no larger limit than
the hard cap. Exhaustion rejects new ingress/send before acceptance, retains old
records, and allows draining/processing/ack of already accepted records when the
result fits. Reserve acknowledgement/terminal bookkeeping headroom at admission.
Inbox admission charges the current encoded document plus, for every pending
entry, six times its payload length and 16 KiB of terminal/effect headroom. The
factor accounts for JSON escaping expansion when base64 payload becomes an inline
domain object; processing replaces raw ingress with the domain record rather than
duplicating it. This deliberately conservative quota covers full effect growth.
An additional 4 KiB global inbox margin covers revision/ack bookkeeping. Configured
quotas govern admission; reducing them cannot block already reserved processing
or custody-reducing acknowledgements within the hard limits.

No automatic pruning of replay tombstones, pending messages or inbox receipts.
Operators must provision capacity or perform a separately reviewed offline
migration; deleting state is not supported recovery. No background expiry purge.
This finite retention policy trades lifetime throughput for bounded state and
unambiguous replay; it is not an unlimited production mailbox service.

Reopen validates schema, identity, receipt uniqueness, logical uniqueness, state
transitions and payload digests. Corruption is unavailable, never an empty spool.
All mutations load and copy state, validate limits, write through W07, then return
success. No cache is updated ahead of disk. Fixed errors expose no payload/path.

## Review and acceptance gates

Before implementation: independent review resolves custody, authorization, atomic
domain effects, finite retention, quotas and additive API compatibility above.
Then implement spool, HTTP, inbox/receiver in separate commits and run:

1. Exact-bound/near-limit messages, >64 small messages, FIFO paging and oversize
   rejection before accepted send; preserve complete encoded framing.
2. Provider write/read failure, cancellation and reopen; no accepted data loss.
3. Receive response failure/truncation/disconnect followed by identical redelivery.
4. Failed ack persistence retains messages; lost ack response retries harmlessly.
5. Local preflight/ingress/domain commit/ack-state write failures retain custody.
6. Restart after send, receive, ingress, ack, domain commit and lost response.
7. Mixed valid/malformed peers, receipt conflicts, duplicate logical content,
   provider/inbox quota exhaustion, namespace/owner/source/epoch authorization.
8. Repeated/concurrent pulls do not duplicate domain records; callbacks must not
   run under an exposed receiver lock that they can reenter.
9. Old public APIs, JSON cases and errors remain compatible; enumerate deliberate
   v2 additions. Compile and run existing consumer integration tests.

Report local proof separately from hosted/platform qualification. The legacy
SD-02/SD-03 reproductions remain demonstrations of the compatibility path's limits;
new reliable-path tests must establish the replacement behavior explicitly.
