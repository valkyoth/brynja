# Kani Verification Policy

Status: v0.22.0 SHA-256 arithmetic and padding harnesses admitted

Brynja builds, tests, and releases on the active stable Rust toolchain. Kani is
compiler-integration-sensitive and therefore uses a separately documented
compatible pairing, following the same model as `base64-ng`.

## Current Pairing

- Active release toolchain: Rust `1.97.1`.
- Supported crate range: Rust `1.90.0` through `1.97.1`.
- Kani verifier toolchain: Rust
  `1.90.0-x86_64-unknown-linux-gnu`.
- Pinned verifier: `cargo-kani 0.67.0`, upstream tag `kani-0.67.0`, commit
  `4feaaad1d6a2378a6ff6caa3b4fc5d6999c7bb5d`.
- Current proof result: two bounded SHA-256 harnesses cover checked message
  length and the exact one-block/two-block padding decision.

Updating Brynja's active stable compiler does not imply that the installed Kani
release supports that compiler. Kani evidence records its verifier/compiler
pair separately from the crate build matrix. The crate MSRV is never lowered
or the release compiler held back merely to accommodate Kani.

`scripts/check-kani.sh` verifies this policy, the installed pairing, the exact
two-harness inventory, and both proof results when the verifier is available.
An unavailable verifier remains an explicit skip and is not proof evidence.

The v0.22.0 harnesses prove only that checked byte-length admission exactly
matches the less-than-2^64-bit FIPS domain and that every valid buffered length
selects the correct one- or two-block padding form. They do not prove SHA-256
functional equivalence, collision resistance, constant-time machine code,
backend equivalence, or independent cryptographic verification.

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
proof of equivalence. v0.155.0 completes the machine-readable claim register
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
scripts/check-kani.sh
```

Ordinary repository and GitHub CI runs execute only
`scripts/check-kani.sh --policy-only`. That fast check proves that the admitted
harness inventory and source confinement have not drifted; it does not claim
the proofs ran. Before a tag is created, the local tag gate runs
`scripts/check-kani.sh --required` and fails closed unless the pinned verifier
and both harnesses pass. The crates.io publish preflight consumes that already
required pre-tag evidence instead of repeating the verifier run. This keeps
hosted CI bounded while retaining Kani as mandatory tag evidence.

Revisit this document whenever the active stable Rust release, MSRV, Kani
release, verifier toolchain, proof bounds, or harness inventory changes.
