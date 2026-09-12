# W11: Auth operation ownership and cancellation

> Historical record for the revision named below. See [current status](../STATUS.md).

Auth already owns its public types and implementation after the module
reorganization. This pass removes the unused error-writing wrapper and addresses
operation lifetime; it does not count the earlier facade removal again.

HTTP and host protected-store calls run outside the shared service mutex. Each
operation carries its caller's context and an owner generation. Sign-out advances
that generation and cancels outstanding operations before attempting cleanup.
A committed sign-in also supersedes older work. Obsolete HTTP completions cannot
publish a token, profile or diagnostic, or delete a newer same-owner credential.
Copied Service values share the generation and storage reservation.

Strict storage calls reserve the owner without holding its mutex. A concurrent or
reentrant call that needs the same storage returns ErrStorageUnavailable promptly.
This is a deliberate concurrency behavior change: hosts may retry after the outer
operation finishes. During HTTP, Status, Profile and SignOut can run normally.
Legacy local file operations remain serialized; their concurrent StartSignIn
replacement behavior is preserved. Reservations are released during panic
unwinding, so a host recovering from a callback panic does not strand the owner.

SignOut returns ErrSignOutIncomplete when strict storage is already reserved. It
has canceled outstanding work but cannot promise that an in-flight host mutation
has stopped. Wait for that operation to finish and retry SignOut. A token write
that completes after invalidation is removed using only its owned revision; a
newer revision is never deleted by that rollback. Cleanup receives a separate
three-second context because the original operation has been canceled. Host
stores must honor cancellation to bound callback duration.

Strict completion captures the token revision before HTTP. Both the commit and
failed-profile cleanup compare against that revision, preventing an old request
from overwriting or deleting a newer credential written by a different owner.
The existing bounded session CAS still coordinates separately constructed
services. Owner generations do not coordinate sign-out across independent
services or processes; hosts must share one Service for a coordinated lifecycle.
Token and local profile files remain separate records, not a cross-store
transaction. Failed or canceled partial publication can require sign-out retry
or reconnect; a successful sign-out never claims unfinished cleanup.

Caller contexts reach protected Get, Put, Delete, revision reads and CAS retries.
OAuth body-read failures are now classified instead of ignored. Existing timeout
messages and exported error identities remain. Constructors have no caller
context and retain the original migration preflight/readback/rollback procedure.
Public imports, signatures, JSON schemas, strict no-fallback storage, redirect
validation, PKCE, profile redaction and migration fixtures remain unchanged.

Deterministic regression tests pause token/profile HTTP and protected mutations,
exercise callback reentry and caller cancellation, and preserve newer credentials
through stale cleanup. Existing strict two-service claim/quota/replay tests and
legacy replacement tests remain enabled. Local source/export validation and
independent review are recorded in the campaign evidence directory; hosted Linux
runtime/race and Windows CI remain final publication gates.
