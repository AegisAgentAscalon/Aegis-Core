// Package identitygate contains the private implementation for the Aegis Core
// Identity Gate foundation.
//
// The implementation owns local session state, scope recomputation, cadence
// policy resolution, prompt provenance checks, local profile validation,
// verification-receipt evaluation, explicit mock verification, and safe packet
// generation. Public consumers must import pkg/identitygate rather than this
// package.
package identitygate
