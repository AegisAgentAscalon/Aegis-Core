# W18: cumulative audit, corrections and publication

Date: 2026-09-12. Baseline W17: `f8f140ac88acd28bdca9951f2014b202eecd01f0`.
This pass reviews the accumulated campaign across all eleven public domains,
private persistence/identity/storage implementations, examples and integration
policy. Separate reviewers own identity/auth, sync/relay and state/updates;
corrections receive an independent review before the candidate is frozen.

## Corrections

| Area | Reproduced defect | Correction |
| --- | --- | --- |
| Cloud manifest | Unencodable timestamps caused ignored JSON errors and identical empty-input hashes for different manifests | Reject normalization, comparison, verification and storage with existing invalid-manifest semantics |
| Device Link | A damaged private-key seed or a different canonical key could produce successful readiness/signing results with unusable signatures | Verify seed-derived key bytes and bind signing to the persisted identity; preserve rejected state |
| Device Link fingerprints | JSON encoding failures could collapse public identity, registry and proof fingerprints to empty-input hashes | Reject unencodable fingerprint input at validation/export boundaries |
| Profile Mesh snapshots | An unencodable outer timestamp could collapse the fingerprint while import discarded that timestamp | Reject encoding failure before fingerprint acceptance or state mutation |
| Profile Sync local metadata | Injected clocks could reenter a store while its mutex was held | Sample operation time before locking and pass it into private helpers |
| Relay local development provider | Cleanup clocks could reenter provider status while its mutex was held | Sample cleanup time before locking; retain the separate query-time filter |
| Updates body reads | Cancellation was masked as provider/download failure | Return the existing cancellation sentinel for failed reads with a canceled context; keep ordinary failure and successful commit behavior |
| Updates workflow wait | A deadline could wait indefinitely behind unrelated provider work | Use a shared cancellation-aware workflow gate, retaining serialization and copied-handle ownership |
| AppBridge | Unsafe provider identifiers leaked through display-name fallbacks | Sanitize identifier fallbacks before display projection |

Regression tests cover invalid cloud/identity/mesh timestamps, retained authority,
seed/public-half/whole-key corruption, valid signing, unchanged rejected key files,
clock reentry, canceled and ordinary body failures, unchanged update authority and
artifacts, canceled workflow wait/gate reuse, and safe/unsafe display fallbacks.
Historical test files and fixtures are retained. No public API or schema change
is intended. The local metadata adapter uses a pre-lock observation time; it does
not gain multi-process transactional authority from this callback correction.

## Validation and publication boundary

The frozen local matrix comprises full source and committed-export tests, vet,
formatting, Windows lock/persistence tests, minimum compiler compilation, Linux
cross-compilation, module/vulnerability checks, typed API/wire/error probes,
Updates/Profile Mesh behavior probes, the expected legacy audit, and detached
VargBot compilation/focused integration checks. The external campaign evidence
binds commands, inputs, reviewed source hashes, logs and the exact candidate SHA.
These checks are required before branch publication; this record is authored
before the final matrix and is not itself a passing test receipt.

The reviewed branch proceeds through a pull request and exact-head hosted checks
before main is updated. Hosted Linux runtime/race, Windows and committed-export
results must succeed for that source. Current run receipts are available in
[GitHub Actions](https://github.com/AegisAgentAscalon/Aegis-Core/actions/workflows/go.yml).
The separate campaign publication receipt binds those run/job/checkout identities
to the local seal. A different merge SHA requires its own exact-head verification.

Core remains experimental. SD-02/SD-03 are retained limitations of legacy exchange;
reliable v2 needs explicit consumer adoption. Migration still requires stopping
old writers, and native state cannot safely be opened by downgraded writers.
Trusted-local filesystem, no power-loss proof, retained disclosed artifact paths,
host-owned installers/protected stores and real-provider qualification limits
remain as documented. This pass does not tag, release, install or qualify a
production deployment. No universal speedup or overall source reduction is claimed.
