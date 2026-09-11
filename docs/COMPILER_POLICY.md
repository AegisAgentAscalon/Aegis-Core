# Go compiler and compatibility policy

The module language floor remains Go 1.22.0. Compatibility CI compiles all
packages and tests with Go 1.22.12; that historical compiler is not approved
for releases or security validation.

Normal tests, vet, Linux race checks and security CI use Go 1.27.1, the patched
release selected for W00 on 2026-09-11. Keep the exact CI pin current with
supported Go security releases. Changing that pin requires ordinary tests and
a fresh vulnerability scan, not a language-floor bump. The release history is
https://go.dev/doc/devel/release.

Security CI runs govulncheck v1.8.0 and fails on reachable vulnerabilities.
Tool dependencies belong to the scanner process, not this library's go.mod.
Local validation may select the compiler with GOTOOLCHAIN=go1.27.1 without
changing the installed system compiler. Release artifacts must be built with
the approved patched compiler, even if older compilers can compile the source.

W00 does not prove hosted CI or a Linux race pass. Those checks require their
own results before release acceptance.
