# Opting into reliable relay delivery

Use the separate v2 provider and receiver when messages must survive a failed
response or application process restart. Legacy ReceiveEnvelopes and SyncManager
PullRemote retain their existing at-most-once behavior.

## Host provisioning and access

Create one relay.FileReliableMailbox for a private directory with fixed ProviderID,
Namespace, MailboxID and OwnerDeviceID. Retain its Mailbox() reference, including
the generated epoch. Reopening preserves that reference. Share the owning instance;
do not open independent writers for the same path. Provisioning is host-owned.

Serve it with NewReliableRelayHandler. Its required Authorize callback receives
the HTTP request, action, full mailbox reference and asserted send source device.
Authenticate credentials, then check mailbox membership, action permission and
sender/device ownership. Client-supplied owner fields and receipts are not authority.
The host owns transport security and authorization policy.

Routes are POST /v2/envelopes, /v2/mailboxes/receive and /v2/mailboxes/ack. There is
no unauthenticated bypass or destructive fallback.

## Sending and receiving

SendReliableEnvelope takes version 2, the full mailbox reference and a RelayEnvelope.
The inner envelope retains protocol version 1. Set its namespace, target mailbox
and device to the reference; compute PayloadHash with relay.PayloadSHA256. Retry
the exact envelope after an ambiguous response. Changed timestamps or payload
under the same logical message ID conflict with accepted content.

ReceiveBatch does not consume. Defaults are 64 entries and 1 MiB encoded, including
framing/base64/metadata. Smaller item counts are supported; the byte limit is fixed.
Validate the complete batch before accepting anything. ReliableEnvelopeDigest
defines Go JSON full-envelope SHA-256. HTTPRelayClient performs those checks.

Persist receipt content before AcknowledgeBatch. Unknown outcomes require recovery;
they are not acknowledgements. Retry lost ack responses with the same reference
and receipt IDs. Tombstones make repeated acknowledged IDs harmless. Callers own
bounded retry/backoff scheduling; the library starts no workers.

## Profile Sync adoption

Create profilesync.ReliableInbox in its own private directory with the same mailbox
reference. NewReliableSyncReceiver takes that inbox, the provider or HTTPRelayClient,
the existing local SnapshotStore and a TrustVerifier. Omitting the verifier leaves
metadata pending trust review, matching legacy behavior.

Call the receiver's PullRemote. Read remote metadata through the inbox's
ListRemoteSnapshots and ListRemoteProposals; inspect ListReceipts for pending,
applied, rejected and awaiting-ack records. ReceivedAt records ingress; ProcessedAt
and Freshness.ObservedAt record classification. Historical freshness is not a live
health check. Remote metadata remains subject to review and independent authority.

For sending Profile Sync, JSON-encode a public profilesync.SyncEnvelope into the
relay payload. Inner and outer namespace, source device and message ID must match;
payload-kind metadata must be consistent. Existing RelaySyncTransport uses v1.

The reliable inbox does not copy effects into legacy LocalMetadataStore files.
Choose its projections as the consumer's authoritative remote metadata view and
make any migration explicit. Existing applications continue on v1 until changed.

## Capacity and guarantees

Defaults are 1,024 lifetime receipt records and 32 MiB state per spool/inbox.
Inbox admission reserves processing space. Replay identities are retained, making
this a finite-capacity mailbox. New admission fails at capacity; accepted work can
drain, including after admission limits are reduced. There is no automatic prune,
reset or rotation API. Offline backup/migration requires a reviewed procedure.

W07 flushes and closes temporary files before replacement. The contract covers
single-owner process-restart recovery in host-managed directories, not power-loss
durability or cross-process transactions. Hosted platform/race qualification and
consumer adoption remain separate requirements.
