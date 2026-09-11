# Brynja v0.24.38

Status: implemented; exceptional pentest/retest and three-platform native KMAC
collection PASS; awaiting final release/GitHub/CodeQL checks.

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
KMAC evidence was collected after retest at `3578aeac` and reviewed. Older
Keccak-only records were not substituted for these keyed high-level KMAC APIs.

The [owner-supplied retest](../security/pentest/v0.24.38.md) confirms both
Low/informational notes addressed with no new issues. The
[native index](../security/kmac-execution-native.json) binds Intel Xeon Platinum
8488C, AWS Arm Neoverse-V1 and Apple M2 Pro records to 267 source inputs and
Rust 1.98.1. Each route passed 268 official/oracle cases; each platform passed
four lifecycle tests and the 1,024-permutation actual-kernel check. Intel covered
portable/preferred-absence/static/preferred execution; both Arm platforms also
covered required hosted execution. Final release qualification remains pending.

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

The final live standards check detected newly reported RFC 9002 erratum 9169.
It is tracked, not applied, under the existing caller-owned QUIC recovery
boundary. The metadata refresh changes no cryptographic implementation or
native evidence. The owner-approved planner correction gives the generated
protocol register an exact-path eight-MiB cap while retaining the four-MiB
code/lockfile cap, mandatory metadata checks and fail-closed behavior. Scoped
KMAC verification is selected again; no unapproved full sweep was started.
