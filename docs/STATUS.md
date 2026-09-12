# Current engineering status

This page is the current status index. Dated documents in [audits](audits/README.md)
record their own source revisions; their findings and counts are historical.

Core remains experimental, with compatible public imports under `pkg/`. Reviewed
W15 is `52477dfcab5b9332b8d6e035fae9b8426a99381a`. Its local source/export matrix
passed 26 gates, including 1,335 ordinary test/subtest passes and six skips,
unchanged API/wire/error contracts, and detached VargBot compile/focused checks.
The expected tagged legacy audit still reproduces SD-02/SD-03. Reliable v2 custody
and inbox handling do not migrate applications off the legacy exchange API.

W16 consolidates test fixtures and example setup and updates this documentation
index. Library production code, public APIs, schemas and persisted fixtures are
unchanged. Its coverage map and validation record are in the
[W16 audit](audits/2026-09-12-w16-consolidation.md).

## Authoritative documentation

| Subject | Current document |
| --- | --- |
| Module structure, ownership and compatibility | [Architecture](ARCHITECTURE.md) |
| Migration, locking, recovery and retention limits | [State persistence](STATE_PERSISTENCE.md) |
| Reliable delivery protocol and legacy boundary | [Reliable delivery](RELIABLE_DELIVERY.md) |
| Update source and signing policy | [Update sources](UPDATE_SOURCES.md) |
| Identity Gate contracts and limits | [Identity Gate](IDENTITY_GATE.md) |
| Release/API status and deprecation | [Release policy](RELEASE_POLICY.md) |
| Consumer adoption and rollback | [Consumer migration](CONSUMER_MIGRATION.md) |
| Supported compiler policy | [Compiler policy](COMPILER_POLICY.md) |
| Remaining engineering and consumer responsibilities | [Roadmap](ROADMAP.md) |

W14's Profile Mesh and Updates generations support cooperating writers on trusted
local filesystems. Stop old writers before migration; old readers cannot safely
roll back native state. Previously disclosed artifact paths are retained, with no
automatic committed-blob garbage collection. Power-loss, network-filesystem and
exactly-once external installation guarantees are outside this evidence.

W18 performs the cumulative source audit and corrects cloud encoding, device-key
integrity, callback lock ownership, update cancellation and status redaction.
See the [W18 record](audits/2026-09-12-w18-final-audit.md) for corrections and the
publication gate. W17's earlier local readiness is recorded in the
[W17 record](audits/2026-09-12-w17-integration.md).

Exact-commit hosted Windows/Linux execution and Linux race results are published
in [GitHub Actions](https://github.com/AegisAgentAscalon/Aegis-Core/actions/workflows/go.yml).
Check the run's recorded checkout against the source commit being evaluated;
this document is written before those runs and does not certify their result.
Reliable-v2 consumer adoption, provider qualification and production deployment
remain separate work. A repository update does not imply a tag or installation.
