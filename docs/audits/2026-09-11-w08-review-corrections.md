# W08 review corrections

Baseline: 4c0b7b5fd2e4ca4c057c251ae2a960adbe72ee35.

Allowlist IDs now use dedicated sorting/deduplication that preserves exact values.
They no longer pass through descriptive-text redaction, which discarded IDs
containing "secret" and could turn a restrictive list into an unrestricted one.
Registration and import validate the representation that will actually be saved;
blank and unknown references remain rejected. Descriptive metadata filtering is
unchanged. Valid device IDs are authorization data, not credential text.

Allowed devices must exist, but only the selected current host must be active,
trusted and fresh. A removed, revoked or stale alternative no longer blocks a
switch to a healthy allowed device. Policy entries are not automatically pruned,
and selecting an unavailable or non-allowlisted host still fails. The original
W08 stale-alternative test now expects acceptance across all writers, matching
this separation of permission from availability. Historical schema-1 presence
semantics and unsupported-hint rejection are unchanged.

Regressions cover sole/mixed allowlists with duplicate IDs, registration and both
import schemas, reopen/export/import stability, unauthorized host rejection, and
removed/revoked/stale-host failover with policy retained and dead targets rejected.
The new regressions fail on unchanged baseline production before these fixes.

Historical API/JSON/error vectors and persisted fixtures remain unchanged. A v2
fingerprint newly computed from an ID that old normalization redacted now includes
that ID; compatibility evidence does not claim those broken normalization cases
have identical fingerprints. Previously discarded allowlist entries cannot be
reconstructed from the stored empty list and are not silently guessed or repaired.

Exact-commit checks are retained in the control repository under
evidence/aegis-core-w08-correction-20260911. Hosted/platform qualification remains
pending; W14 still owns hint storage and atomic import. No W09 work is included.
