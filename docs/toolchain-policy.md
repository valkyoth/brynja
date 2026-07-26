# Toolchain Policy

Status: enforced policy

The MSRV is Rust `1.90.0`; the pinned full-gate toolchain is Rust `1.97.1`.
The pin was verified against the official stable Rust release on 2026-07-21.
Before every release, `scripts/check_latest_tools.sh` must query the official
stable manifest, crates.io tool versions, and action tags. A stale pin fails
closed and is updated in a dedicated reviewed change without raising the MSRV.
CI security and SBOM tools are recorded in `scripts/ci-tools.lock` with exact
versions and independently maintained SHA-256 hashes of their crates.io
archives. `scripts/install-ci-tools.sh` verifies each archive before building
it with its packaged lockfile; a version or checksum mismatch fails closed.

Every promised stable toolchain is checked explicitly. Nightly tools may add
evidence but cannot be required to build published crates.
