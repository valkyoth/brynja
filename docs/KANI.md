# Kani Verification Policy

Status: v0.24.18 legacy SHA-1, SHA-2, FIPS 202, KMAC, TupleHash, and ParallelHash policy harnesses admitted

Brynja builds, tests, and releases on the active stable Rust toolchain. Kani is
compiler-integration-sensitive and therefore uses a separately documented
compatible pairing, following the same model as `base64-ng`.

## Current Pairing

- Active release toolchain: Rust `1.98.1`.
- Supported crate range: Rust `1.90.0` through `1.98.1`.
- Kani verifier toolchain: Rust
  `1.90.0-x86_64-unknown-linux-gnu`.
- Pinned verifier: `cargo-kani 0.67.0`, upstream tag `kani-0.67.0`, commit
  `4feaaad1d6a2378a6ff6caa3b4fc5d6999c7bb5d`.
- Current proof result: ten SHA-2 harnesses cover the shared byte and exact-
  bit 64-bit and 128-bit message domains, byte-padding decisions, public-output
  failure atomicity, and complete secret-output failure clearing; six
  SHA-3/SHAKE harnesses plus two hardened-owner harnesses cover exact byte and quotient/remainder bit-counter
  exhaustion, canonical FIPS 202 bit shapes and low-bit masks, plus every
  byte-to-lane mapping in the Keccak-f[1600] state and the hardened final-bit
  output partition and mask bounds; two SP 800-185 harnesses cover complete
  length-encoding bounds, and two KMAC harnesses cover exact strength
  classification and fixed-tag bit-length acceptance; two TupleHash harnesses
  cover item reservations and encoding boundaries, and one ParallelHash
  harness covers exact leaf-count division over its admitted symbolic domain.
  One legacy SHA-1 harness proves both acceptance and the exact returned sum
  for every pair of u64 current/additional bit lengths against u128 arithmetic.

Updating Brynja's active stable compiler does not imply that the installed Kani
release supports that compiler. Kani evidence records its verifier/compiler
pair separately from the crate build matrix. The crate MSRV is never lowered
or the release compiler held back merely to accommodate Kani.

`scripts/assurance/check-kani.sh` verifies this policy, the installed pairing,
the exact twenty-six-harness inventory, and all proof results when the verifier is available.
An unavailable verifier remains an explicit skip and is not proof evidence.

The SHA-2 harnesses prove only their stated checked byte/bit-length,
byte-padding, and four-byte output-failure properties. Compiler evidence and
behavior tests cover the full hardened owner regions separately. The shared
FIPS 202 harnesses prove only that input/output byte-counter admission matches
`u128::checked_add`, terminal bit lengths retain exact whole-byte/remainder
decomposition, canonical shapes and low-bit masks are exact, and each of the
200 Keccak state bytes maps to one in-bounds lane and byte shift. They do not
prove permutation equivalence,
digest correctness, collision resistance, constant-time machine code, backend
equivalence, or independent cryptographic verification.

The SHA-1 harness is
`engine::proofs::sha1_bit_exhaustion_matches_wide_arithmetic` in
`brynja-legacy-sha1`. Run `rustup run 1.90.0 cargo kani -p brynja-legacy-sha1`
to check it independently. This full-width arithmetic proof does not prove
SHA-1 compression correctness, collision resistance, cleanup, or protocol
admission. SHA-1 remains a collision-broken, explicitly isolated legacy hash.

## Admission And Claims

Arithmetic and cryptographic milestones add bounded proof harnesses beside the
code they examine. Each report must name:

- the exact implementation symbol and property;
- supported width or parameter;
- whether the proof is symbolic full-width, sound
  limb-count-parameterized, or reduced-width algorithm/harness validation;
- the Kani version, verifier Rust pairing, command, assumptions, unwind and
  resource bounds, and result; and
- every residual gap.

Production-width vectors and independent differential tests are evidence, not
proof of equivalence. v0.203.0 completes the machine-readable claim register
and residual-gap audit; it does not retroactively convert bounded models into
full-width proofs.

An unavailable or incompatible Kani installation is an explicit skip, not a
proof. Any milestone that requires a proof must remain incomplete until the
required harness succeeds on its documented pairing or the release plan is
changed through a separately reviewed numbered exception with replacement
evidence. Brynja must not claim Kani-complete, cryptographically verified, or
formally verified behavior from this v0.4.0 policy foundation.

## Commands

```bash
cargo install --locked kani-verifier --version 0.67.0
cargo kani setup
cargo kani --version
scripts/assurance/check-kani.sh
```

Ordinary repository and GitHub CI runs execute only
`scripts/assurance/check-kani.sh --policy-only`. That fast check proves that the admitted
harness inventory and source confinement have not drifted; it does not claim
the proofs ran. Before a tag is created, the local tag gate runs
`scripts/assurance/check-kani.sh --required` and fails closed unless the pinned verifier
and all harnesses pass. The crates.io publish preflight consumes that already
required pre-tag evidence instead of repeating the verifier run. This keeps
hosted CI bounded while retaining Kani as mandatory tag evidence.

Revisit this document whenever the active stable Rust release, MSRV, Kani
release, verifier toolchain, proof bounds, or harness inventory changes.
