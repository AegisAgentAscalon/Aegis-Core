# W07 persistence contract

Scope: a private internal/filepersist package, then separate Updates and Profile
Sync migrations. No schema migration, new dependency, CAS replacement, database,
multi-file transaction, W04 inbox, or cross-process lock is introduced.

## Contract and review decisions

- Each metadata/artifact root has one trusted host writer. Per-service mutexes do
  not coordinate independent instances/processes. Concurrent readers are supported;
  concurrent logical writers and hostile mutation of ancestors are not supported.
- Paths must name regular files under real directories. Reject symlink/reparse
  paths, directory/device targets, traversal components and Windows reserved/ADS
  paths. Check ancestors before use and recheck the final file/opened identity.
  This is defense in depth in host-owned roots, not an openat-style adversarial
  filesystem sandbox. Host ACLs must exclude untrusted writers.
- Create missing directories with 0700; preserve existing ancestor permissions.
  Requested storage directories use 0700; temporary metadata files use 0600.
  Unix permissions are meaningful there; Windows inherits the directory ACL and
  chmod is not a confidentiality boundary. Host setup owns Windows ACL policy.
- Write into an exclusively created same-directory temporary file, check every
  write, flush and close, recheck cancellation/path policy, then rename once.
  Every failure before successful rename preserves destination bytes. Cleanup
  always attempts to close/remove the owned temporary file; cleanup errors are
  surfaced. Never remove the destination to retry. Newly created empty directories
  may remain after failure. Crash-left temporary files are ignored, not scavenged
  while a potentially active writer could own them.
- Cancellation is checked before IO, between read/write chunks, and immediately
  before replacement. Ordinary file syscalls cannot be interrupted mid-call.
  Successful rename is the commit point: later cancellation does not report a
  rollback or turn committed success into failure.
- JSON reads consume at most limit+1 bytes, require a regular file and a single
  complete JSON value. Domain/schema validation remains in each owner. Updates
  metadata uses a 64 MiB bound (headroom over its 4 MiB manifest limit); Profile
  Sync retains its 8 MiB bound. Writers enforce the corresponding read bound.
- Encodings remain byte compatible: Updates indented JSON without final newline;
  Profile Sync indented JSON with its existing final newline.

## Platform behavior and durability limits

Use the standard library replacement operation once, never its unsafe fallback.
Inspection of the Go 1.27.1 Windows source confirms os.Rename calls MoveFileExW
with MOVEFILE_REPLACE_EXISTING and no copy/delete fallback. Same-directory checks
prevent cross-volume moves. Windows sharing/ACL errors are returned, preserving
old bytes. Test successful overwrite, creation, missing source and sharing denial
on Windows; reader/writer stress checks classify permission errors separately
from missing/truncated contents. Linux uses rename, whose same-filesystem atomic
visibility is covered by the same tests in Ubuntu CI. Cross-compilation is not
Linux runtime proof. Other platforms inherit os.Rename without added guarantees.

Temporary File.Sync and Close precede rename. This provides flushed file contents
and destination-preserving replacement, not guaranteed power-loss durability.
No parent directory flush is claimed or attempted: a post-rename flush error
would occur after commit and cannot honestly imply preserved previous bytes.
W04 durable delivery still needs its protocol/storage design and validation.

References: [Go Rename](https://pkg.go.dev/os#Rename),
[MoveFileExW](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw).

## Gates

Primitive fault tests must pass before either owner is migrated. Faults cover
create, chmod, short write, write, sync, close, replace, cancellation and cleanup;
all preserve existing destination bytes and clean owned temporaries where the OS
allows cleanup. Test malformed/oversized JSON, symlinks, unsafe parents, permissions,
reopen behavior, metadata byte compatibility and old API/error fixtures.
Independent review and hosted Windows/Linux/race execution remain explicit gates;
local self-review and cross-compilation must not be labeled independent or hosted.
