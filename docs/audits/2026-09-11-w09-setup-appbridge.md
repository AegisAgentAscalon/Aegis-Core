# W09: Setup State and AppBridge

Baseline: corrected W08 `348cc602e7e7d3ac74c3d63d9d6798d752a5de25`.

Setup State already owns its public contracts and aggregation directly. Commit
`ad354df` removed its internal mirror before the numbered repair sequence; W09
does not recreate it or claim the historical 150-line saving again. Existing
external API and aggregation tests remain in place.

AppBridge now separates public contracts, status entry points, owner acquisition,
pure projection, setup bindings, sanitization and action forwarding. Setup bindings
define enabled-provider traversal and display order together. Update setup and
diagnostics share one acquisition and sanitization path with explicit private
projection policies. Relay setup and diagnostics share their card projection.
There is no new public interface, framework, persistent service or consumer migration.

The setup policy still propagates owner errors and blocks unconfigured Updates;
infrastructure diagnostics still turn these conditions into nonfatal warnings.
Unknown or blocked security posture still prevents readiness. Disabled capabilities
do not fetch owner state. Each result uses one owner observation, and mutable
provider fields are still copied before sanitization. Public strings, card/issue
ordering and nil/empty collection shapes are preserved.

Physical production lines (including imports, comments and blank lines):

| Scope | W08 corrected | W09 | Net |
| --- | ---: | ---: | ---: |
| Setup State | 155 | 155 | 0 |
| AppBridge | 1,010 | 1,008 | -2 |
| Library (`pkg` + `internal`, excluding tests) | 20,201 | 20,199 | -2 |

Recalibration: the original 20,605-line audit predates the already completed
2,228-line structural reduction to 18,377. Subsequent reliability work and W09
bring the library to 20,199: 406 fewer lines than the audit, or about 2.0%.
The original 2,000–3,000-line hypothesis is retired as a future saving target.
Remaining packages must measure concrete residual duplication from their current
baseline; already removed public/internal facades cannot be counted again.
No runtime-speed or binary-size improvement is claimed from this partition.

Validation receipts are maintained outside the source in the control workspace's
`evidence/aegis-core-w09-20260911`. They bind final tests, API/wire/error checks,
consumer compilation and a clean export to the committed candidate. The W09
differential probe compares 1,024 public scenarios, including all 128 capability
enablement combinations, missing/failing providers, update availability/degradation,
relay and security posture, and owner read counts. Retained regression tests assert
the strict/nonfatal policy difference and prevent duplicate update reads.

This is local implementation evidence. Hosted Windows/Linux and Linux runtime/race
qualification remain pending. Legacy SD-02/SD-03, external v2 consumer adoption,
and W14 durable hints/atomic import remain separate work. W10 is not part of W09.
