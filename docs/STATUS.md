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
| Supported compiler policy | [Compiler policy](COMPILER_POLICY.md) |
| Remaining engineering and consumer responsibilities | [Roadmap](ROADMAP.md) |

W14's Profile Mesh and Updates generations support cooperating writers on trusted
local filesystems. Stop old writers before migration; old readers cannot safely
roll back native state. Previously disclosed artifact paths are retained, with no
automatic committed-blob garbage collection. Power-loss, network-filesystem and
exactly-once external installation guarantees are outside this evidence.

Hosted Windows/Linux execution, Linux race qualification, reliable-v2 consumer
adoption, provider qualification and production deployment remain separately
pending. W17 integration/release readiness and W18 final review/GitHub publication
are future passes. No publication or consumer installation follows from W16.
