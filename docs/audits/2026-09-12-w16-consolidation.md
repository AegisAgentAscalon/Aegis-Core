# W16 test, example and documentation consolidation

Baseline is reviewed W15 `52477dfcab5b9332b8d6e035fae9b8426a99381a`.
No test declaration or existing named subtest is removed. No behavior is retired.
All six P1 and sixteen P2 audit scenarios remain: the entire tests/auditregression
source tree and every persisted testdata fixture are byte-identical to W15.
Legacy SD-02/SD-03 remain the expected tagged audit failures; no new claim of
legacy delivery reliability is made. All library production Go files are unchanged.

## Successful constructor setup

59 repeated successful NewService + Fatal(error) blocks become two package-local
fixture builders. Each builder accepts the unchanged cfg, uses the same constructor
(Updates still supplies nil Apply), marks itself t.Helper, and calls t.Fatal on
error before returning a service. Negative constructor tests still invoke public
constructors directly. Nine affected follow-on err assignments acquire a local
short declaration after the former setup declaration is removed; checks remain.
The external W16 preparation evidence records every baseline function/line/call replacement in fixture-mapping.json.

| Package/file | Replaced successful setup blocks |
| --- | ---: |
| `pkg/auth/protected_store_test.go` | 11 |
| `pkg/auth/service_test.go` | 14 |
| `pkg/updates/generation_concurrency_test.go` | 2 |
| `pkg/updates/service_test.go` | 28 |
| `pkg/updates/source_lanes_test.go` | 2 |
| `pkg/updates/source_policy_test.go` | 2 |

Updates JSON/error safety assertions share their identical forbidden-text loop.
Both callers retain marshal/error admission and lowercasing; every forbidden token
and every consuming test remains. No shared helper enters production packages.

## Examples and import checks

Smoke/proof snapshot builders call one example-only Snapshot constructor with the
same namespace/profile/source IDs, timestamps and synthetic signatures. Their
output checks retain the shared path/raw-payload exclusions, exact per-example
payload markers and extraForbidden semantics. Smoke's unchanged JSON write/close
setup moves to WriteJSON in that helper. Existing behavior/output tests remain.

The two import tests permit exactly examples/internal/exampledata from the consumer
and inspect its Go files too. All other private/example dependency rejections stay.
The no-named-consumer scans now include the moved helper. This is the narrow fixture
exception authorized by W16, not permission to call private Core owner APIs.
Identity Gate's smoke program is unchanged.

## Documentation and validation

STATUS.md is the current status index, linking to one owner document per API,
security, persistence and ownership topic. Old dated audits receive only a historical
banner; their original report bodies are preserved. README no longer treats the
pre-repair reorganization report as current. Architecture/roadmap acknowledge the
implemented W14 generations and W15 work without claiming hosted qualification.

The external W16 preparation coverage-inventory.json records unchanged production/audit/fixture hashes and the
full retained test declaration list. The final matrix compares runtime test/subtest
identities with W15, checks source/export parity, and runs existing compatibility,
consumer, compiler and security gates. Test/example lines and runtime are reported
separately from library code; source reduction is not a shipped-binary speed claim.

## Acceptance evidence

This implementation record describes the coverage-preserving changes. Final frozen-source
validation, independent review, exact line deltas and runtime observations are sealed in
the campaign workspace under evidence/aegis-core-w16-20260912. W17 and W18 remain separate
work packages; this record does not claim hosted CI, Linux runtime/race or publication.
