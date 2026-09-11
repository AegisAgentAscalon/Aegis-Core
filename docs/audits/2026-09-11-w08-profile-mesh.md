# W08: Profile Mesh resource invariants and explicit hint rejection

Historical initial pass. The subsequent [review corrections](2026-09-11-w08-review-corrections.md)
refine allowlist normalization and separate alternative-host permission from liveness.

Baseline: W04 correction 8822bcfea47ffad2f53803647640c14c34f557c4.

Resource registration, host changes and snapshot imports share validateResource:
resource identity/type/owner, single-host mode, known availability, active trusted
host references and allowlist membership. Default profile-data host selection goes
through the same checks. Corrupt hosting configuration fails instead of becoming
an implicit empty host. Live resource validation reads the device registry once
for all references. SetResourceHost deliberately sets availability to available;
it validates the resulting resource rather than preserving the previous status.

Device lifecycle and presence checks share validateActiveDevice. Schema 2 imports
use the service clock. Schema 1 retains historical-state interpretation at its
recorded UpdatedAt (falling back to the service clock when absent); importing old
state does not refresh LastSeen or assert present availability. Live host queries
continue to evaluate the current clock. Legacy fixture bytes are unchanged.

Nonempty RelayHints or EndpointHints now return ErrInvalidProfileSnapshot before
any import write. SD-06's silent data loss is resolved by explicit rejection, an
allowed W08 outcome. Durable hint storage remains unimplemented and belongs with
W14's generation-format work; no new sidecar or transaction scheme was added.
Schema 1 and 2 both reject unsupported hints. Empty-hint imports retain their
existing format and the public fingerprint/JSON contract remains unchanged.

Import still writes four files sequentially. Every failed write returns an error;
earlier files may already have changed. This is not an atomic import or automatic
rollback claim. The failure regression blocks the last replacement and requires
ErrStorageUnavailable. Full generation recovery remains W14 work.

Regression coverage compares valid and invalid candidates across registration,
host updates and both import schemas, checks rejection leaves stored bytes intact,
and covers default-host allowlists, corrupted default configuration, historical
presence, hint rejection and partial-write error reporting. The control repository
retains exact-commit validation under evidence/aegis-core-w08-20260911.

SD-05 and SD-06 no longer reproduce. Legacy W04 SD-02/SD-03 remain outside W08.
Hosted Windows/Linux and Linux runtime/race qualification remain separate gates.
No public API removal, dependency change, generation migration or W09 work.
