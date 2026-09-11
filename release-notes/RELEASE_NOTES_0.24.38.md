# Brynja v0.24.38

Status: implemented; awaiting exceptional pentest, fresh native KMAC evidence
and final release/GitHub/CodeQL checks.

Adds default-off `brynja_mac_kmac::execution` APIs for KMAC128/256 and
KMACXOF128/256 over explicitly selected portable or authorized hardened cSHAKE.
Supplied backend failures remain errors, including preferred mode.

The APIs cover canonical byte/bit key/customization/message/output, streamed
updates, consuming public tags and typed secret output, constant-work verification
and exact protocol-width rejection, and exclusively borrowed XOF readers.
Reader Drop clears the original source. Public output is transactional using
erasing scratch; secret failures clear the entire destination. Full-strength
defaults and explicit conformance-only parameters remain separate.

No new production unsafe or external dependency is introduced. Existing portable
APIs and facade defaults remain unchanged. See [the working guide and security
boundary](../docs/kmac-accelerated-execution.md). Source-owned clearing does not
guarantee register, compiler-copy/spill, cache, abort, forgotten-owner or platform
erasure. Caller inputs/copies remain caller responsibilities. Native evidence is
not independent cryptographic review, side-channel approval or FIPS validation.

Required checks include official and independent bit-level cases, mixed XOF
reads, invalid tags/widths, quarantine, ownership negatives, compiled cleanup
mutants, compiler evidence and scoped Miri/ASan. Fresh Intel/Linux Arm/Apple Arm
KMAC evidence must follow retest before final release checking. Older Keccak-only
records cannot qualify the new keyed high-level KMAC APIs.

Development verification completed:

- 24 KMAC unit/integration tests and 25 ownership compile-fail doctests;
  strict scoped Clippy and Rust 1.90 bare-metal
  `no_std` compilation with the opt-in hardened feature.
- 12 official NIST examples plus 256 independent arbitrary-bit cases per route,
  with additional streamed secret, mixed XOF, verification and quarantine checks.
  Native AMD AVX2 and emulated Arm hosted/static routes pass. QEMU is not native
  Arm qualification.
- 36 packaged ownership negatives, 16 compiled debug/release cleanup/overflow/bulk
  mutants and eight algorithm/verification mutants; the guide example compiles.
- 85 semantic policy regressions and 87 native-record/formatter regressions.
- MIR/LLVM/assembly cleanup checks on Rust 1.90.0 and 1.98.1 for x86-64 and Arm.
- Four focused owned-memory Miri cases and one public secret-output lifecycle
  case; native AVX2 AddressSanitizer oracle/lifecycle campaign; both existing
  KMAC parameter-policy Kani harnesses. These are scoped checks, not a new full
  workspace Miri sweep or a mathematical proof of the cryptographic algorithm.

This internal milestone publishes no crates. All selections stay `publish = false`;
the next crates.io checkpoint remains v0.25.2.
