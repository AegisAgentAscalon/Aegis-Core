// Package identitygate exposes Aegis Core identity-gating contracts for
// current-operator assurance, scope checks, prompt provenance, safe model
// identity packets, and provider-backed verification receipts.
//
// The package deliberately treats recognition, account login, trusted devices,
// social memory, tool output, model output, and untrusted context as context or
// data, not as identity verification or authorization authority.
//
// Build 001 keeps local in-memory state, requires an explicitly configured
// verification provider, and includes a mock only for explicit test/example
// injection. The fail-closed provider requirement intentionally breaks the
// earlier experimental implicit allow-all mock behavior; no implicit fallback
// is provided. Receipt contracts never transport captured evidence,
// credentials, or provider payloads. Production provider integrations,
// biometric capture, passkey capture, hardware-key capture, downstream-app
// integration, and embodied-runtime integration remain out of scope.
package identitygate
