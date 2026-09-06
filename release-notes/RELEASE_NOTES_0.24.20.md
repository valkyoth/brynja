# Brynja 0.24.20 Release Notes

Status: implemented; local candidate verification PASS; exceptional pentest pending

## Summary

Freeze the portable SHA-1/MD5 consumer boundary before acceleration, and improve
impact-selected Miri coverage. No production Rust, algorithm, external dependency
or backend admission changes. The facade advances to internal 0.24.20; all
crates, including changed support crates, remain unselected for publication.

## Deliverables

- Standalone allocation-free no_std acceptance library and runnable host example,
  exercising both legacy leaves through ordinary/hardened byte and arbitrary-bit
  one-shot and streaming APIs, secret output and explicit public declassification.
- Four fixed/file messages and sixteen canonical bit messages for each family;
  independent expected digests, partitions, length rejection, output atomicity,
  cancellation, Drop and recoverable-unwind checks. The larger official vector
  and independent-oracle campaigns remain in each primitive's gate.
- Replay the unchanged consumer against real core/hash-core/SHA-1/MD5 `.crate`
  archives. A positive-controlled downstream compiler test rejects sixteen
  modern/legacy, FIPS, protocol, signature, password and owner-copy misuses.
  Absent future API symbols are not proof of a future protocol's security.
- Source/corpus freeze, corruption regressions, hostile archive rejection,
  compiler-matrix, no_std target, Miri and AddressSanitizer bindings.
- Semantic Miri selection across signed-baseline committed, staged, unstaged,
  deleted and untracked changes. Local version bumps no longer trigger old
  complete suites. Changed owners and dependents receive full registered groups;
  unchanged groups receive smoke. Unknown/shared implementation impacts fail
  closed, and public crates.io checkpoints always run every full group.

The cheap workspace, policy, dependency, compiler, Kani and AddressSanitizer
checks remain mandatory. Miri evidence stays bound to its actual verifier;
nightly-only smoke does not reclassify old full evidence as newly executed.

## Security and remaining work

SHA-1 and MD5 are collision-broken legacy compatibility algorithms, not modern
authentication, signatures or password hashing. They remain outside the modern
facade, TLS, PKIX and FIPS graphs. Both rows remain **In progress** until the
v0.24.21–v0.24.23 acceleration and final evidence disposition. No new AWS or
Apple hardware evidence is needed for this unchanged portable implementation.

Hardened owners clear their documented source-owned memory; this does not erase
registers, compiler copies/spills, caches, swap, dumps, DMA or caller copies, and
Drop cannot run after forget, abort or forced termination. No independent
cryptographic review, FIPS validation or deployment approval is claimed.

Rust 1.90.0–1.98.1 remains the supported matrix. The Kani verifier is separate.
See [portable acceptance](../docs/legacy-hash-portable-acceptance.md),
[focused assurance](../docs/focused-assurance.md) and the
[candidate pentest report](../security/pentest/v0.24.20.md).

## Release conditions

Local verification passes: complete repository gate, all twelve Rust lanes,
bare-metal targets, independent frozen digests, actual package replay, mutation
and non-admission tests, stage-selected Miri, ASan (without LeakSanitizer), all
27 Kani harnesses, advisory/tooling checks and zero-publication dry-run. The
final focused Miri test execution totals about three minutes on the local host;
full groups remain unchanged and required for affected/public-checkpoint work.

Record completed local verification in the report, obtain the exceptional
pentest, then commit its disposition and wait for green GitHub/CodeQL. Tag only
with explicit owner approval. This milestone publishes zero crates.
