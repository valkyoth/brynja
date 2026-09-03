# Toolchain Policy

Status: enforced policy

The MSRV is Rust `1.90.0`; the pinned full-gate toolchain is Rust `1.98.0`.
The pin was verified against the official stable Rust release on 2026-08-29.
Before every signed tag, `scripts/ci/check_latest_tools.sh` must query the official
stable manifest, crates.io tool versions, and action tags. A stale pin fails
closed and is updated in a dedicated reviewed change without raising the MSRV.
CI security and SBOM tools are recorded in `scripts/ci/ci-tools.lock` with exact
versions and independently maintained SHA-256 hashes of their crates.io
archives. `scripts/ci/install-ci-tools.sh` verifies each archive before building
it with its packaged lockfile; a version or checksum mismatch fails closed.

Every promised stable toolchain is checked explicitly. Nightly tools may add
evidence but cannot be required to build published crates.

The Rust 1.98 full gate denies all Clippy warnings except
`chunks_exact_to_as_chunks`. That style-only lint is explicitly allowed at the
gate boundary so a compiler refresh does not force semantically neutral churn
through already reviewed fixed-width cryptographic chunk loops. Correctness,
safety, panic, arithmetic, allocation, and project-specific source-policy
checks remain enforced.

Kani follows a separate verifier pairing because it is compiler-integration
sensitive. The active release toolchain remains Rust `1.98.0`, while
`cargo-kani 0.67.0` is pinned to the documented compatible Rust
`1.90.0-x86_64-unknown-linux-gnu` execution toolchain. This does not lower the
crate MSRV, hold back stable Rust, or turn policy-only status into proof.

`assurance/policy.toml` additionally pins Kani, AFL++, honggfuzz, Miri, and
sanitizers by exact source revision. Miri and sanitizers use the latest
available `nightly-2026-09-03` at Rust revision `2e2b193f8ada105f27608b7be81c293e0d7292cb`.
These tools are external to Cargo
manifests. Ordinary builds do not download or execute them; each owning
milestone must recheck upstream state and record exact campaign evidence.
