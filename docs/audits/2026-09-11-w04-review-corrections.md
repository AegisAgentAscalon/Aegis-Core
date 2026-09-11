# W04 review corrections

Baseline: a88c8a23fceca298366b6e65a641969a6b50afe9.

- ReliableEnvelopeDigest rejects invalid UTF-8 metadata before the provider
  commits acceptance. Go 1.22 reproduced an accepted envelope becoming unreadable
  after JSON repair changed its digest. Go 1.27 normalized it differently; the
  explicit rejection keeps the reliable contract consistent across toolchains.
  Legacy envelope validation is unchanged; valid Unicode remains accepted.
- The receiver durably rejects a decoded domain whose JSON digest cannot be
  computed. A +24:00 timestamp could decode but fail subsequent encoding, leaving
  acknowledged ingress pending and blocking later work. Snapshot and proposal
  regressions cover first ingress and recovery of already acknowledged records,
  healthy peer progress, and terminal dispositions surviving restart.

Before-fix logs and exact-commit correction validation are retained in the control
repository under evidence/aegis-core-w04-correction-20260911. Historical W04 and W07
candidates and evidence remain intact. No storage migration or legacy API change.
These changes prevent new mailbox poisoning; they do not repair a mailbox already
corrupted by an earlier accepted invalid-UTF-8 envelope. Such state still fails
closed and requires separately reviewed recovery. Previously pending inbox
timestamp cases recover through the normal corrected receiver.

Hosted Windows/Linux CI, Linux runtime/race qualification and external consumer
v2 adoption remain pending. No W08 work, push, merge or release is included.
