# September module reorganization and audit status

> Historical record for the revision named below. See [current status](../STATUS.md).

The local structural candidate starts at test-cleanup commit `85720d7`, whose
production source matches audit candidate `2006392`. It consolidates Auth,
Device Link, Profile Mesh, Setup State and Updates into their public package
owners, partitions large implementations, and retains eleven public package
paths in one Go module. See [the architecture map](../ARCHITECTURE.md).

The public service types keep one pointer to private state so copying a service
continues to share its owner and lock. Ordinary DTO mirrors are removed; storage
and explicit backup representations remain private where their fields differ
from public JSON. Identity Gate retains its focused internal engine, and Secret
Store retains its development adapter. Distinct test cases move with their
implementation owners.

Validation for this candidate includes the full ordinary suite and vet, public
type/method/field/constant compatibility checks, concrete-type comparability and
positional-literal checks, 894 synthetic public JSON comparisons, existing
golden and legacy-format tests, a baseline-to-candidate-to-baseline persistence
probe, and a sampled VargBot consumer compiled with a
temporary module replacement. The consumer's source dependency declarations
remain unchanged. Race execution and hosted CI remain separate outstanding
gates; the local environment has CGO disabled and no supported C compiler.

The compiler used for the audit and this structural pass is Go 1.26.0. The
earlier vulnerability scan reported standard-library findings; a supported,
patched compiler and renewed scan remain required maintenance work. This pass
does not establish a clean security or deployment baseline.

## Open findings from the full audit

These failures were reproduced on the pre-reorganization audit source. This
structural change does not implement their repairs. Their identifiers preserve
the audit register so follow-up patches can be assessed separately.

| ID | Failure to repair |
| --- | --- |
| IG-01 | Recognition can renew expired or idle verification before expiry refresh. |
| IG-02 | An untrusted input fragment can retain caller-supplied instruction authority. |
| IG-03 | Audit callbacks under the state lock can deadlock on reentry. |
| IG-04 | Stored profiles can alias caller-owned slices or maps. |
| IG-05 | Unknown or held delivery channels can pass a protected-context decision. |
| UA-01 | Detached artifact metadata is not fully bound to the verified signed manifest. |
| UA-02 | Idempotent or conflicting staging can leak full pending artifact copies. |
| UA-03 | Expired or consumed strict Auth sessions can exhaust the bounded session quota. |
| UA-04 | A valid token can overwrite the reconnect indication for a corrupt profile. |
| UA-05 | Delete-before-rename replacement can lose a valid destination on failure. |
| SD-01 | Distinct cloud object IDs can map to the same sanitized filename. |
| SD-02 | An HTTP batch can exceed the whole-response cap after messages are dequeued. |
| SD-03 | A store failure or malformed batch after dequeue can lose accepted messages. |
| SD-04 | A caller-supplied future relay query time can expire another namespace's data. |
| SD-05 | Initial Profile Mesh resource hosting can violate its host allowlist. |
| SD-06 | Accepted snapshot hints are discarded through import/export. |
| SD-07 | Comparing cloud manifests from different namespaces can report remote-newer. |
| SD-08 | The memory discovery adapter can alias mutable provider input or output. |
| AR-01 | AppBridge sanitization can mutate provider-owned slices. |
| AR-02 | An unknown posture can be presented as ready. |
| AR-03 | Auth and update status composition can read twice and lose the second error. |
| AR-04 | A successful Setup State provider can expose an unsafe summary. |

The original audit proposed repairing critical failures before consolidation.
The user's subsequent instruction requested the module reorganization first.
That changes the execution order, while leaving the correctness gates open.
Repair these failures with focused regression cases and rerun the affected
consumer contracts before further changes to persistence or lock scope.
