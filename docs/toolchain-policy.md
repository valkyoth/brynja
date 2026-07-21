# Toolchain Policy

Status: enforced policy

The MSRV is Rust `1.90.0`; the pinned full-gate toolchain is Rust `1.97.1`.
The pin was verified against the official stable Rust release on 2026-07-21.
Before every release, `scripts/check_latest_tools.sh` must query the official
stable manifest, crates.io tool versions, and action tags. A stale pin fails
closed and is updated in a dedicated reviewed change without raising the MSRV.

Every promised stable toolchain is checked explicitly. Nightly tools may add
evidence but cannot be required to build published crates.

