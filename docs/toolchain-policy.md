# Toolchain Policy

Status: enforced policy

The MSRV is Rust `1.90.0`; the pinned full-gate toolchain is Rust `1.97.1`.
The pin was verified against the official stable Rust release on 2026-07-27.
Before every signed tag, `scripts/check_latest_tools.sh` must query the official
stable manifest, crates.io tool versions, and action tags. A stale pin fails
closed and is updated in a dedicated reviewed change without raising the MSRV.
CI security and SBOM tools are recorded in `scripts/ci-tools.lock` with exact
versions and independently maintained SHA-256 hashes of their crates.io
archives. `scripts/install-ci-tools.sh` verifies each archive before building
it with its packaged lockfile; a version or checksum mismatch fails closed.

Every promised stable toolchain is checked explicitly. Nightly tools may add
evidence but cannot be required to build published crates.

Kani follows a separate verifier pairing because it is compiler-integration
sensitive. The active release toolchain remains Rust `1.97.1`, while
`cargo-kani 0.67.0` is pinned to the documented compatible Rust
`1.90.0-x86_64-unknown-linux-gnu` execution toolchain. This does not lower the
crate MSRV, hold back stable Rust, or turn policy-only status into proof.

`assurance/policy.toml` additionally pins Kani, AFL++, honggfuzz, Miri, and
sanitizers by exact source revision. These tools are external to Cargo
manifests. Ordinary builds do not download or execute them; each owning
milestone must recheck upstream state and record exact campaign evidence.
