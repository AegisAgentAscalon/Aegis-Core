// Package identitygate exposes Aegis Core identity-gating contracts for
// current-operator assurance, scope checks, prompt provenance, safe model
// identity packets, and local/mock foundation behavior.
//
// The package deliberately treats recognition, account login, trusted devices,
// social memory, tool output, model output, and untrusted context as context or
// data, not as identity verification or authorization authority.
//
// Build 001 is a foundation implementation. It uses local in-memory state and a
// mock verification provider only; real biometric, passkey, hardware-key,
// downstream-app, and embodied-runtime integrations are intentionally out of
// scope for this build.
package identitygate
