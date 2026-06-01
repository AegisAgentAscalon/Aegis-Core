# Generic Consumer Proof

This example is a neutral proof that Aegis Core can be consumed through public APIs only. It is not a real app integration, not a production template, and not a hosted relay or cloud sync example.

The proof demonstrates:

- AppBridge setup overview output with disabled and degraded capabilities represented as non-fatal status.
- Relay `LocalDevProvider` mailbox delivery, delivery receipts, and duplicate message handling.
- Profile Sync metadata snapshot/proposal push and pull through the public relay transport adapter.
- `LocalMetadataStore` persistence for profile sync metadata across store re-open.
- Safe partial-failure behavior for disabled sync, missing transport, and corrupt local metadata.

The example uses temporary directories only. It does not require network access, credentials, OAuth configuration, production services, or user-machine state. It does not store private profile data, raw relay payload dumps, or external provider credentials.

Run it with:

```powershell
go test ./examples/generic-consumer-proof
go run ./examples/generic-consumer-proof
```

The JSON printed by `go run` contains only safe booleans and counts. It intentionally omits filesystem paths, relay payload bytes, mailbox internals, and provider internals.
