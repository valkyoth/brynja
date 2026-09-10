# Brynja v0.24.34

Status: implemented; awaiting exceptional pentest and fresh native evidence.

## Verification workflow first

- Select expensive repository, compiler-matrix, sanitizer, Miri, Kani and
  native/QEMU campaigns by changed inputs and affected consumers.
- Explain selected and reused suites; retain a cheap repository-wide baseline.
- Stop an uncertain scope before expensive execution. Correct the classification
  or obtain explicit owner approval for the exact plan fingerprint.
- Keep full public crates.io checkpoints automatic. An unapproved uncertain
  scope is incomplete verification, never a successful or skipped release gate.
- Include SHA-2's nested consumer and disabled optional-dependency lock subsets
  without accepting changed package pins or unknown edges.
- Bind approval to the commit, baseline, changed inputs and build/verifier
  environment; reject stale tokens and unreviewed compiler/analysis overrides.

## Workflow-pass verification

Planner and dispatcher regression tests, selected/full Miri shell traces,
selected/full Kani shell traces, semantic dependency-scope negative fixtures,
repository policy tests, workspace native tests, Clippy, documentation and SBOM
checks passed. Unchanged cryptographic Miri/Kani/sanitizer campaigns were not
rerun for this tooling-only pass. This is not the final v0.24.34 release check.

## Hardened SHA-2 execution

- Adds default-off `hardened-execution` leaf features and complete named
  SHA-224/256/384/512, SHA-512/224, SHA-512/256 and general SHA-512/t byte/bit
  streaming, one-shot, cancellation, preflight and consuming-output APIs.
- Keeps ordinary execution separate. Secret output transfers an affine owner;
  public output requires explicit declassification. General secret output
  retains its parameter identity without public byte import.
- Adds separate owner-backed SHA instruction kernels for x86_64 SHA-256 and
  AArch64 SHA-256/SHA-512. CPU scratch clears after every operation and on
  unwind/Drop; real hardened KAT failure quarantines the original authority.
- Reuses all eight hardened hash-owner regions. A mutable-update guard clears
  and fails retained streams on backend failure/unwind. Secret-output errors
  clear the complete destination; public-output errors preserve it.
- CPU scratch clearing uses a default-off first-party `brynja-core` edge;
  no external dependency was added. All default constructors stay portable.
- Splits the old mixed ParallelHash/legacy sanitizer command so a selected
  ParallelHash check no longer also runs unrelated SHA-1/MD5 campaigns.
- Proves portable Miri dependency isolation from both baseline and current
  lock graphs: this CPU change selects SHA-2 and CPU ownership, without rerunning
  unrelated portable Keccak-family Miri suites. Native CPU integration tests
  retain their broader scope. Missing proof still requires owner approval.

Local packaged acceptance covers 240 named NIST bit vectors, 4,590 general-t
oracle cases, twelve ownership/classification negatives, algorithm mutations,
ten live destructor-region observations and twenty compiled clearing mutants.
Native AMD and supplemental AArch64 QEMU routes match portable results.
Optimized MIR/LLVM/assembly cleanup checks pass under Rust 1.90.0 and 1.98.1
for x86_64 and AArch64 with recoverable unwind enabled.

See [the API, owned-region inventory and reproducible checks](../docs/sha2-hardened-execution.md).
Selected Miri, AddressSanitizer and Kani checks passed, as did the twelve-version
Rust compatibility matrix, strict Clippy, refreshed RustSec scan and cargo-deny.
Miri covers portable ownership, not instruction semantics; Kani's existing
portable harnesses do not prove the new CPU kernels. The initial over-broad
Miri run was stopped after dependency isolation was established; the final
SHA-2/CPU selection completed successfully. Repository checks passed, with the
metadata tail resumed after correcting the roadmap status label. The new kernel
bodies need a fresh exceptional pentest and native Arm/Mac evidence before
tagging; the post-pentest final release check remains a separate step.

Erasure claims exclude registers, compiler-created copies/spills, caches,
swap, crash dumps, DMA, abort, forced termination, `mem::forget` and caller
inputs/copies. No FIPS, independent-review or military-deployment claim is made.

The facade advances to 0.24.34; support versions and external dependency pins remain
unchanged. All publication flags remain false; the next public checkpoint is
v0.25.2. Independent cryptographic verification and FIPS validation stay absent.
