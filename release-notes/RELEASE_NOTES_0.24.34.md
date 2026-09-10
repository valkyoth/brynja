# Brynja v0.24.34

Status: exceptional retest and final local checks passed; awaiting green GitHub before tagging.

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

Second pentest follow-up: generic ASan ownership tests could skip the x86
instruction kernel. A separate mandatory native SHA-NI/SSE2 ASan runner now
checks hardware first and requires the actual 512-block kernel execution marker.
The corrected nine-test run passed on the local AMD host. The tag gate now
requires reviewed, commit/source/route-bound native Linux x86, Linux Arm and
Apple Arm artifacts. Missing captures block tagging but not ordinary CI;
the owner retest passed and all three native lanes are now archived. No production kernel logic changed.

Pentest follow-up: the private buffer-length setter now rejects oversized
lengths before mutation and every caller propagates failure. Boundary, retained
state cleanup and compiled reset/bounds mutations prevent regression. Arm
secret-kernel comments explain the required endian conversions; their logic is
unchanged. Both Low findings are fixed and the owner retest passed.

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
bodies passed the exceptional retest. A Linux Arm CPU-identity whitespace bug
discovered during collection was fixed with a tabbed-field capture regression.
All three lanes were recollected at `10c8bdfa`: Intel Xeon Platinum 8488C,
AWS Neoverse V1 and Apple M2 Pro. Each applicable portable/static/hosted route
passed 240 named and 4,590 general-t cases; kernel markers confirm 512 block
comparisons per supported hardened kernel. The [archived evidence](../assurance/sha2-hardened-native/README.md)
binds all 170 tested inputs; the Mac account path is redacted. The post-pentest
final release check remains a separate step.

Final local verification completed on 2026-09-10: selected repository acceptance,
bare-metal and supplemental QEMU checks, twelve-version Rust compatibility,
AddressSanitizer (including actual SHA-NI hardened execution), SHA-2/CPU Miri,
selected Kani proofs, current standards/tooling/dependency checks, SBOM and
release policy all passed. The native index remains bound to `10c8bdfa`.
Documentation-hash corrections were checked by resuming the failed acceptance
step, without restarting completed cryptographic campaigns. The release script
selects zero crates and refuses publication for this internal milestone.

CI follow-up: the defensive buffer-length change shifted the SHA-2 Drop impl
source span. Its exact MIR registry pin now matches line 83, with a fast
source-span regression and successful Rust 1.90.0/1.98.1 compiler cleanup checks.
No production code, cleanup proof requirement or native capture input changed.

Final CI metadata correction: refreshed the separate SHA-2/SHA-3 README hash
bindings after documentation edits. Release metadata validation now checks all
five acceptance hash closures, with stale-README regression tests and no Rust
campaign execution. SHA-2/SHA-3 public and packaged acceptance passed again.
The GitHub README groups Rust 1.90.0–1.98.0 into one compatibility row and keeps
1.98.1 separate; the exact tested compiler matrix is unchanged.

Erasure claims exclude registers, compiler-created copies/spills, caches,
swap, crash dumps, DMA, abort, forced termination, `mem::forget` and caller
inputs/copies. No FIPS, independent-review or military-deployment claim is made.

The facade advances to 0.24.34; support versions and external dependency pins remain
unchanged. All publication flags remain false; the next public checkpoint is
v0.25.2. Independent cryptographic verification and FIPS validation stay absent.
