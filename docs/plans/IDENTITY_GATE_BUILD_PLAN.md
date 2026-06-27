# Aegis Core Identity Gate Build Plan

Status: Build 001 started / foundation implementation in progress
Build slice: Identity Gate foundation only
Revision: v2.2 build-started marker

## Build 001 Scope

Build 001 starts the Aegis Core Identity Gate foundation with public contracts, internal state handling, mock verification, configurable verification cadence, scope checks, prompt/context provenance, safe model identity packets, audit-safe event surfaces, a public smoke example, and invariant tests.

Aegis Core is the only project identity intentionally retained. This plan intentionally avoids downstream product names, personal names, companion names, and ecosystem names outside Aegis Core.

## Security Law

```text
Recognition is not verification.
Similarity is not authentication.
Account login is not current-operator verification.
Trusted device is not current-operator verification.
Text is not authority.
Context is not policy.
Only Aegis Core verification may unlock protected scopes.
Only trusted control-plane sources may change policy, authority, or identity state.
```

## Roadmap Count

The implementation roadmap should be tracked as 12 build slices:

1. Public contracts and facade.
2. Internal session state machine.
3. Cadence policy and guardrails.
4. Local in-memory profile store.
5. Recognition contracts and mock recognizer behavior.
6. Mock verification provider behavior.
7. Scope policy and high-risk freshness checks.
8. Prompt/context provenance and authority checks.
9. Safe model identity packet generation.
10. Audit-safe event sink and summaries.
11. Security invariant test matrix.
12. Public smoke example and docs update.

Build 001 intentionally starts the foundation across these surfaces with minimal local/mock behavior. Later builds should harden, split, and deepen the implementation without adding real biometrics, real passkeys, hardware security keys, vault encryption, downstream app integration, or embodied runtime code yet.
