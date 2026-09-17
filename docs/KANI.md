# Kani Verification Policy

Status: 32 inventoried production-source harnesses; separate hardened-batch qualification campaigns

Brynja builds, tests, and releases on the active stable Rust toolchain. Kani is
compiler-integration-sensitive and therefore uses a separately documented
compatible pairing, following the same model as `base64-ng`.

## Current Pairing

- Active release toolchain: Rust `1.98.1`.
- Supported crate range: Rust `1.90.0` through `1.98.1`.
- Kani verifier toolchain: Rust
  `1.90.0-x86_64-unknown-linux-gnu`.
- Pinned verifier: `cargo-kani 0.68.0`, upstream tag `kani-0.68.0`, commit
  `0d2328a93f0e0ff66132d6bfa1a7d884877cf862`.
- Bundled backend: CBMC `6.11.0`; Kani's own compiler uses
  `nightly-2026-08-21`. The Rust `1.90.0` pairing above is the launcher
  toolchain, not a claim that proofs execute on that stable compiler.
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
  Three ordinary-batch harnesses cover atomic checked budgets for narrow
  SHA-2, wide SHA-2 and Keccak. The three legacy MD5 proofs described below
  complete the 32-harness production-source inventory. Separate injected-source
  hardened-batch/ParallelHash campaigns are not included in that inventory.

Updating Brynja's active stable compiler does not imply that the installed Kani
release supports that compiler. Kani evidence records its verifier/compiler
pair separately from the crate build matrix. The crate MSRV is never lowered
or the release compiler held back merely to accommodate Kani.

`scripts/assurance/check-kani.sh` verifies this policy, the installed pairing,
the exact thirty-two-harness inventory, and all proof results when the verifier is available.
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

The MD5 harness `engine::proofs::md5_bit_exhaustion_matches_carry` checks
all u128 current/additional bit pairs against overflowing addition. It proves
admission and the returned sum, not compression or erasure. Run
`rustup run 1.90.0 cargo kani -p brynja-legacy-md5 --features batch` for all three
MD5 proofs. The two new `batch::control::proofs` harnesses check every usize
budget/request pair for exact checked subtraction and unchanged budget on
rejection, and prove cancellation consumes no budget. They do not prove SIMD
correctness, cleanup, migration safety, timing or independent verification.

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
cargo install --locked kani-verifier --version 0.68.0
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

## v0.24.48 verifier refresh

The previous final detached sweep passed with Kani `0.67.0`, but the online
freshness check found `0.68.0` before tagging. The
[upstream release](https://github.com/model-checking/kani/releases/tag/kani-0.68.0)
includes soundness and compiler/model changes; old proof results are not
claimed as results under the new verifier. Historical `0.67.0` records remain
unchanged.

The new two-line version banner identifies both Kani and CBMC. The existing
drivers now require that exact identity; regression tests reject stale Kani,
missing or mismatched CBMC, and unsuccessful version commands. The proof
inventory, proof bounds, failure requirements and release approval rules are
unchanged.

On 2026-09-17, fresh Kani `0.68.0` execution passed all 32 inventoried harnesses,
six isolated hardened-batch budget proofs with nine real-source counterexamples,
and all nine isolated ParallelHash proofs with 31 real-source counterexamples.
The latter driver also reran each unmodified proof after its mutations and
exited successfully. These retain the documented bounds, backend/clearing
models and exclusions; they do not prove full cryptographic correctness or
replace the separate final release sweep.
