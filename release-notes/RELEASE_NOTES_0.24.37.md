# Brynja v0.24.37

Status: implementation, focused assurance and exceptional retest complete;
awaiting fresh native qualification and final release verification.

See the [hardened Keccak working guide](../docs/hardened-keccak-execution.md).

This internal milestone adds default-off hardened Keccak execution for all
four SHA-3 hashes, both SHAKE XOFs and cSHAKE128/256. The current working tree
contains thread-bound CPU sessions, separately owned permutation scratch,
absorbing-to-reader transitions, consuming bit finalization, explicit public
declassification and typed secret output. Portable constructors remain unchanged.

The AVX2 and AArch64 paths execute vectorized chi with owner-backed theta,
rho/pi and vector staging. No performance advantage is claimed before measurement.
Seven permutation scratch regions are cleared after each operation and on Drop
or recoverable unwind. The high-level sponge owns and clears lanes, counters,
suffix staging and output staging; execution failures terminate the owner.
Registers, compiler-created copies/spills, caches, aborts, forgotten owners and
platform storage remain outside the owned-memory erasure claim. Caller inputs
and caller-created output copies remain caller responsibilities.

Completed development checks include native AMD AVX2 and AArch64 QEMU comparison
of 1,024 arbitrary permutations per backend, kernel scratch clearing and unwind
quarantine, and native high-level fixed/XOF bit-boundary and output-owner tests.
QEMU is not native Arm evidence. Neither backend is independently reviewed or
FIPS validated by these checks.

Additional development verification completed:

- High-level arbitrary-bit, in-place phase, cancellation, late failure,
  transactional public-output and typed secret-output checks.
- 54 packaged ownership/classification negatives and 22 compiled debug/release
  region-removal mutants with live Drop observation of eleven owned regions.
- 19 semantic policy regressions and 87 native-record tamper regressions.
- MIR/LLVM/assembly clearing checks at Rust 1.90.0 and 1.98.1 on x86-64 and Arm;
  focused native AVX2 AddressSanitizer and Miri owned-memory/staging tests.
- Static AVX2 and static/hosted Arm packaged execution; Arm uses QEMU here,
  not native qualification. Bare-metal no_std and MSRV checks pass.
- Compiler namespace regressions prevent the existing SHA-2 cleanup checker
  from confusing its Operation/Scratch owners with the new Keccak owners.

No register/spill erasure or compiler-proven non-unwinding call-chain claim is
made. Cleanup's non-panicking behavior also relies on the pinned clearing
primitive and lifecycle tests. Existing native records were not rewritten to
claim coverage of this new code. The tag gate requires reviewed Intel, Linux
Arm and Apple Arm hardened Keccak records before allowing a tag.

After a clean exceptional pentest, collect fresh native Intel, Arm and Mac
evidence and complete the release review before waiting for GitHub/CodeQL.
This milestone selects zero crates.io packages. The next public checkpoint
remains v0.25.2.

Pentest hardening follow-up: scratch indexing now returns a typed failure instead
of silently substituting zero or omitting a write. Error propagation preserves
caller state and retains cleanup/quarantine. Boundary tests and compiled mutants
cover that behavior. A bounded, replayable SHAKE/cSHAKE operation-sequence property
campaign now runs in packaged native checks and is required by native evidence.
Existing all-feature CI doctests and 54 packaged ownership checks already cover
the reported non-Send/non-Clone concern. The owner supplied a clean retest of
8b4b88ba confirming all three findings resolved and no new vulnerabilities.

Ordinary CI now uses explicit diagnostic entrypoints instead of a saved release
approval fingerprint. Known scope retains affected checks; uncertain scope warns
and runs the shared baseline, without granting release approval or marking
deferred verification passed. Tagging retains all local approval/evidence gates.
This CI-only follow-up does not change the native-capture input closure.
