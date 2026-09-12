# W10: Profile Mesh ownership and contract partition

Baseline: W09 `e1b5c49`, followed by documentation-only accounting correction
`d996491`. The existing `pkg/profilemesh` owner and public service pointer semantics
were established in `ad354df`; W10 does not claim that move a second time.

The remaining mixed files are partitioned by responsibility:

- `types.go`: public domain models and error vocabulary.
- `config.go`: configuration, shared identifier syntax and reserved-device names.
- `snapshot_codec.go`: explicit schema-1/schema-2 fingerprinting and normalization.
- `store.go`: private registry envelopes and existing file operations.
- `sync_contracts.go` / `sync_validation.go`: sync metadata contracts and pure
  validation, separate from service/store operations.
- `public_values.go`: caller-owned copies and deliberate metadata normalization.

Identical ID syntax and reserved-name checks are shared. Their differing policies
remain explicit: storage names reject reserved basenames including extensions,
while sync namespaces retain their previous exact-name rule. Owner IDs can contain
"secret"; sync display metadata still rejects unsafe details. The distinct sync
and owner fingerprint grammars remain separate. Redundant trim/device-ID/contains
wrappers are removed, and `maps.Clone` replaces the ordinary map-copy loop while
preserving nil versus empty values. Sanitizing metadata copies remain separate.

No public API/error identity, schema, JSON tag, canonical encoding, store write
sequence or lock boundary changes. Schema 1 remains a historical-state import;
schema 2 requires its canonical fingerprint. Unsupported nonempty hints remain
rejected before writes as established in W08. Durable hints and atomic multi-file
imports remain W14 work; no successful nonempty-hint round trip is claimed here.

Physical production lines, including comments/imports/blanks, change from 2,057
to 2,045 in Profile Mesh: **12 fewer lines**. The library changes from 20,199 to
20,187. Earlier facade reductions are excluded from W10's saving. No runtime-speed
or binary-size claim is made.

The external control workspace's `evidence/aegis-core-w10-20260911` binds tests,
API/wire/error comparisons, old fixtures, consumer checks and clean-export evidence
to the final commit. A public differential probe compares 24 scenario bundles for
config/ID edge cases, owner methods, snapshot export/reimport and sync snapshot,
proposal and branch validation. Domain-policy regressions guard the intentional
differences between shared validators. Existing W08 tests retain schema/hint and
authorization-policy coverage. Hosted Windows/Linux and Linux runtime/race
qualification remain pending, as do legacy SD-02/SD-03 and external v2 adoption.
