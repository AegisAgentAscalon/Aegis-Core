# W02 — update artifact authority and staging cleanup

> Historical record for the revision named below. See [current status](../STATUS.md).

UA-01: selection and downloaded/verified cache validation reselect the artifact
from the policy-validated manifest for the configured platform/architecture.
Detached artifact fields, including signature metadata, must match that
selection. The signed manifest payload format is unchanged.

New private staged records retain the manifest so later description, planning,
lifecycle and handoff validation can recheck signature and artifact identity
without depending on the download cache. The public StagedUpdate DTO is
unchanged. Staged size must match actual bytes, including zero-byte records.

Older staged records without an embedded manifest recover authority from their
existing verified cache when it matches the current policy and staged package.
If that evidence is missing or inconsistent, validation fails with
ErrVerificationFailed; callers must clear and restage from a valid manifest.
Unsigned manifests remain supported only where policy already permits them;
binding provides consistency, not publisher authentication, in that mode.

UA-02: lifecycle preflight now runs before allocating/copying a pending package.
Pending-file removal is deferred on every return. Before committing, staging
rechecks cancellation, configuration/apply state and lifecycle under the
service mutex. Existing record-only operations retain their no-callback policy.

The two original audit cases are ordinary tests now. Additional cases cover
detached hash/size/URL/name/platform/architecture/signature changes, staged
metadata and byte tampering, old-cache recovery, no-op/conflicting restages and
deterministic cancellation after partial copying. The other 18 audited findings
remain outstanding. This change does not replace the shared delete-first file
replacement helper (UA-05/W07), add cross-process transactions, or start W03.

Detailed local results and exact commit/export hashes are recorded by the
control repository under evidence/aegis-core-w02-20260911. Hosted CI and Linux
race validation remain separate release gates.
