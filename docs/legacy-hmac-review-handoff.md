# Legacy HMAC review handoff

This is an author-prepared map of the v0.25.1 implementation and checks, not an
independent security assessment, authenticated execution receipt or release
approval. It does not add a release gate. SHA-1 and MD5 remain explicit legacy
compatibility algorithms, absent from modern facades and protocol negotiation.

## Implementation boundary

The [portable crate](../crates/brynja-legacy-hmac/README.md) owns HMAC framing,
long-key normalization, byte streaming, canonical final message bits, preselected
byte truncation, public/clearing-secret outputs and verification. Its sealed
identities use hardened SHA-1/MD5 state. `LegacyUse` acknowledges compatibility
use; it does not establish key quality or approve an algorithm.

The [hosted crate](../crates/brynja-legacy-hmac-std/README.md) adds distinct Linux
protected and Apple Silicon resident sessions. Each has scalar, SHA-1 hardware
and MD5 SIMD owners. Construction and requests are bounded, keyed work occurs
on the joined worker, and output loans clear session-owned storage. No legacy
owner is added to `brynja-strict` or modern HMAC.

The ordinary scalar route remains scalar under feature unification. SHA-1
hardware owners require complete SHA-NI or Arm SHA-1 deployment authority.
MD5 batches require full aligned AVX2/NEON groups; normalization and suffixes
may select scalar work by public shape before execution. Neither route may
turn an integrity failure into portable fallback.

## Review priorities and existing checks

| Boundary | Check and interpretation |
| --- | --- |
| HMAC framing and policy | RFC 2202 vectors; independent byte/bit models; empty, short and long keys; all supported tag widths; canonical tails and chunk boundaries |
| Scalar state and constructors | Scratch, engine and retained-owner compiler drivers; real public invalid-width Kani harnesses; bounded Miri lifecycle/unwind cases |
| SHA-1 execution | Exact authority before key absorption; both inner/outer owners on failure; native byte/bit differential tests and compiled admission/cleanup mutations |
| MD5 SIMD | All active-slot masks, distinct-lane messages, normalization choices, shared work budget, aggregate verification and transactional outputs |
| Hosted worker | Capture/launch/callback identity, borrowed lifetimes through join, setup rejection, result transport, quarantine and output-loan destruction |
| Failures and cleanup | Cancellation, revocation, recoverable unwinding, malformed inputs, forgotten output loans and injected pre-entry resource failures |
| Packaging and isolation | Fresh extracted archives, exact dependency/feature graphs, compiled ownership negatives, source-only payloads and no modern/protocol dependency edges |

The [hosted qualification guide](legacy-hmac-hosted-qualification.md) states
the exact compiler models, their source premises and their limits. Its checks
are not a whole-stack/register-erasure proof. Review real production callees
as well as the checker: same-repository pins detect drift, not independent
authorization or correctness of the model itself.

## Development results at c5f50477

The current functional/package refresh uses
`c5f504771c3ab8e9f1c4f8bc4c9974e658df58aa`. The exact source archive sent to
the isolated Mac workspace has SHA-256
`f5f6895283de1db2066047743c33c0d23756505f8d112d07d174add75a65bd54`.
These identifiers bind the author's records; they do not authenticate a runner.

All eight extracted-package lanes passed with Rust 1.99.1: leaf, hosted scalar,
hosted SHA-1 hardware and hosted MD5 SIMD on Linux x86-64 and native Apple
Silicon. The leaf runs exercise real SHA-NI/AVX2 or Arm SHA-1/NEON respectively
in debug and release, alongside the portable byte/bit oracles and 28 compiled
negative probes. The three hosted runs require respectively 6, 10 and 11
passing tests with zero failures/ignores in each build profile. Their ownership
negatives reject 28, 39 and 47 probes; each rejects ten scalar cleanup mutations,
with another fourteen SHA-1 or twenty-two MD5 compiled mutations as applicable.
Every restored baseline passes. The Mac's 5,889 archived source files were
compared byte-for-byte again after execution and remain unchanged.

Local records are retained outside published packages under
`release-reports/v0251-package-refresh-c5f50477-linux/` and the corresponding
`-apple/` directory. Commands, compiler identity, host identity, exit statuses
and checker output are kept separately. The package checker captures and
validates underlying Cargo output; these logs are its summaries, not complete
raw transcripts of every child. Do not describe them as a detached receipt.

The sixteen hosted compiler profiles were already author-tested at the
`7b7e8ffd` reconciliation checkpoint. Comparison with `c5f50477` found all 1,310
selected existing inputs unchanged: production source/manifests, five compiler
fixtures, legacy checker implementations, shared HMAC helpers and Cargo setup.
The saved log has exactly the intended compiler/target/panic/SIMD population
and SHA-256 `3d9090c499239189581c478142e14de2609c59d947a19985a3edf1ee6037c4e8`.
This preserves the historical author result; no new compiler execution or
independent qualification is inferred. AArch64 Linux compiler output is not
native Linux Arm execution.

The timing diagnostic separately reconciles sixteen saved observations and
128 campaigns, with zero reported signals, to the unchanged measured source.
Linux captures retain their original dirty-source/history discrepancy; see
the qualification guide. Timing screens do not establish constant time.

The scoped verifier work also passed eleven new Miri tasks, two Kani
invalid-width harnesses and portable/public-metadata ASan with fatal ASan/LSan
options. These do not execute or qualify native protected workers. They are
development runs, not completed detached release campaigns.

## Boundaries that remain explicit

- Existing hash reviews do not independently qualify the new HMAC composition.
  No independent v0.25.1 review is claimed by this handoff.
- Linux protected memory and macOS resident memory are not interchangeable.
  The Apple profile has **no dump-exclusion guarantee**.
- Caller inputs/copies, arbitrary compiler frames/registers, OS/TLS/panic
  internals, snapshots, hibernation, external thread cancellation and fatal
  termination remain outside the stated owned-storage cleanup scope.
- Public lengths, tag policy, active lanes, compression budget and route metadata
  are observable. Applications must pad confidential shape information externally.
- Build-time ISA features require lifetime-wide CPU/OS/deployment guarantees;
  neither startup checks nor this handoff prove migration safety.
- Empty/predictable keys are mathematically accepted but insecure. Applications
  must select trustworthy keys and enforce verification quotas.

Do not report these disclosed limits as a newly broken promise. New violations
of the actual API, memory, failure-classification or evidence scope still need
investigation. Review status, affected release verification, GitHub and explicit
tag authorization remain separate steps; no publication is authorized here.
