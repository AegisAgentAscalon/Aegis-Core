# W05 — Auth lifecycle and status

> Historical record for the revision named below. See [current status](../STATUS.md).

UA-03: strict session append prunes expired records inside the existing revisioned
compare-and-swap mutation. Each conflict retry reloads and recomputes the mutation.
Five live sessions still reject another start. Consumed records remain until
expiry or slot pressure; only the earliest-expiring consumed record is reclaimed
when required. No unconsumed live record is evicted.

The protected v1 schema and five-record bound remain unchanged. Replay rejection
does not require indefinite retention: a consumed state returns ErrSessionConsumed
while retained; an evicted or pruned state returns ErrSessionNotFound. Both reject
before token exchange. A retained consumed marker cannot be reset by session write.
Expiry equality retains the existing consume semantics (expired strictly after
ExpiresAt). Pruning and appending either commit together or leave prior bytes intact.

UA-04: token and profile are read independently and combined into reconnect status.
A valid token cannot clear a bad-profile result. A leftover profile with no token
also requests sign-in. Profiles must contain a nonblank subject, as required by
fresh OAuth profile responses; syntactically valid empty records require reconnect.
SignedIn retains its existing readable-token meaning, including expired tokens;
AccessTokenExpired/NeedsReconnect convey freshness. Strict token corruption and
backend failures still fail closed with existing errors, without plaintext fallback.

Tests include repeated completed sign-ins and replay attempts, expiry boundaries,
five-live quota enforcement, forced two-service CAS conflicts, failed CAS preserving
original records, strict/legacy token-profile matrices and public error redaction.
Existing concurrent consume, PKCE and protected migration tests remain enabled.
No public API, JSON shape, protected record schema or error identity changes.

Thirteen original audit findings remain open. W04 durable delivery still waits
for W07 and protocol review. W06 and W07 are untouched; hosted CI and Linux race
validation remain separate release gates. No push, merge or release.
