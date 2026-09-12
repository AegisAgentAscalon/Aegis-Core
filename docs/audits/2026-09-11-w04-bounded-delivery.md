# W04a — bounded legacy delivery and clock corrections

> Historical record for the revision named below. See [current status](../STATUS.md).

Implements the pre-W07 portion of W04. Legacy LocalDevProvider receive is bounded
at 64 items and 1 MiB encoded JSON; later pages remain queued. Single unpageable
items are rejected before acceptance. HTTP client and handler share those receive
limits. Response delivery still consumes v1 messages before client acceptance.
Custom providers must honor the limits; the handler cannot restore their queue.

Query Now filters results without controlling provider cleanup. Provider time
alone expires mailbox, envelope, replay, endpoint and rendezvous state. Local
snapshot load precedes transport receive, preserving the queue on that failure.
Post-receive reads/writes remain fallible and are not protected by an inbox.

SD-04 is fixed. SD-02 and SD-03 stay open with tagged reproductions for HTTP
response failure and remote-store write failure. The repaired batch-size and
local-read cases now have ordinary tests. Fifteen findings remain open.

The [receive/ack design](../plans/W04_RELIABLE_DELIVERY_DESIGN.md) is ready for
API/protocol review. Durable implementation waits for that review and W07.
No new public interfaces, consumer migrations, push, merge or release. W05 is
untouched. Hosted CI and Linux race validation remain separate gates.
