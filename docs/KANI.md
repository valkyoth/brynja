# Kani Verification Policy

Status: v0.4.0 toolchain boundary established; proof harnesses not yet admitted

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
- Current proof result: no proof harness has been admitted yet.

Updating Brynja's active stable compiler does not imply that the installed Kani
release supports that compiler. Kani evidence records its verifier/compiler
pair separately from the crate build matrix. The crate MSRV is never lowered
or the release compiler held back merely to accommodate Kani.

`scripts/check-kani.sh` verifies this policy and the installed pairing when
available. Until a numbered implementation milestone adds a proof harness, it
must report policy-only status and cannot be represented as a successful
formal proof.

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

Revisit this document whenever the active stable Rust release, MSRV, Kani
release, verifier toolchain, proof bounds, or harness inventory changes.
