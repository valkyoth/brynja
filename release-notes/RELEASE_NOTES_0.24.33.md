# Brynja v0.24.33

Status: implementation candidate; owner review and fresh native functional
collection and final local release verification passed. Awaiting green
GitHub/CodeQL and explicit tagging permission.
Not tagged or published.

## Complete ordinary SHA-2 acceleration

- Add default-off no_std static/runtime execution for SHA-224, SHA-256,
  SHA-384, SHA-512, SHA-512/224, SHA-512/256 and all 510 valid general-t values.
- Provide distinct stream types, byte/bit one-shot APIs, consuming final tails,
  exact digest identities, length preflight and successful-work reports.
- Reuse existing private buffering/padding code with transactional updates;
  retain one borrowed route and explicit internal PublicData classification.
- Execute padding compression through that route; report general-t portable
  IV derivation separately. No silent fallback follows a kernel error.
- Leave hardened owners, kernels, external dependencies and defaults unchanged.
  Only the facade version advances; all publication flags stay false. The next
  public checkpoint remains v0.25.2.

See [usage and boundaries](../docs/sha2-ordinary-execution.md). Generic x86 hosted
detection is unavailable; static SHA/SSE2 requires appropriate deployment.
RISC-V candidates remain separate. These ordinary APIs do not erase memory and
must not process confidential inputs. Independent review and FIPS stay unverified.

## Required verification

Local implementation checks passed for the 240 official bit vectors and 4,590
general-t oracle cases, extracted debug/release packages, seven ownership/type
negatives, twelve algorithm/work-count mutants and five actual-kernel-entry
probes. Native AMD static SHA-224/256 and QEMU Arm static/hosted SHA-2 routes
passed. These are not fresh native Arm/Apple qualification observations.

All twelve registered Rust compiler versions passed the focused execution and
transaction tests. Rust 1.90.0 and 1.98.1 bare-metal no_std builds passed. The ten
existing SHA-2 Kani harnesses passed; they prove their inventoried bounds, not
the new accelerated machine instructions. Focused Miri and AddressSanitizer
passed the changed execution lifecycle and transaction paths.

The verifier-only nightly advances to 2026-09-10 following the official tooling
freshness check; production Rust stays 1.98.1 with MSRV 1.90.0. No external
dependency changes. The refreshed RustSec scan found no known vulnerability.

Repository checks completed successfully, including workspace builds/tests,
strict Clippy, documentation, packaging, policy mutations and SBOM verification.
Stale bindings and the old CPU feature allowlist were corrected and rechecked;
four regressions enforce the new features remaining default-off and correctly
forwarded. These implementation checks do not constitute owner pentest approval.

Official vectors, all-parameter oracle cases, irregular streams, ownership
negatives, wrong-IV/no-op/false-route mutants, scoped memory analysis, supported
compilers, no_std and repository policy must pass. Collect fresh native family
observations after a clean exceptional pentest: older raw-kernel evidence alone
does not prove this integration. Commit the actual report, await green GitHub
and CodeQL, then obtain explicit owner tagging permission. No publication here.

## Collected native observations

The [four-lane archive](../assurance/sha2-execution-observations/v0.24.33/README.md)
records Apple M2 Pro and AWS Neoverse-V1 hosted/static SHA-256 and SHA-512,
plus Intel Xeon 8488C and AMD 9950X3D static SHA-224/256. Wide hashing remains
portable on x86; generic hosted Require rejects and Prefer falls back there.
Every successful mode passed 240 named and 4,590 general-t cases. These are
functional observations, not migration, side-channel, independent-review or
FIPS qualification. No production code changed during collection.

## Final local release verification

The complete local gate passed on `fb719ad8`: repository and package checks,
all twelve supported compiler lanes, bare-metal/QEMU checks, emitted-code
evidence, current standards/tooling/dependency controls, full AddressSanitizer,
all twelve Miri groups, and all 29 inventoried Kani harnesses. Miri selected
full coverage conservatively because the new standalone fixture lockfile
changed its dependency closure; no required check was skipped.

The pentest records PASS with zero open findings. Publication policy and the
dry run select zero crates; all 39 publication flags remain false. Final
status/hash-binding updates are documentation-only and checked separately.
The next crates.io checkpoint remains v0.25.2. No tag or publication was made.
