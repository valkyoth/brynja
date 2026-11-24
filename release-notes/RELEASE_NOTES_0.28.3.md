# v0.28.3 candidate — GHASH public API usability

This internal milestone changes the downstream tests, not the GHASH
implementation. Consumers still opt in to `hazmat-ghash` or
`ghash-runtime-execution`; `Ghash::new` stays portable. The caller supplies
framed input and receives a secret intermediate, not an authentication tag.

The [archive replay](../assurance/ghash-runtime-consumer/README.md) covers
both public entry points on Rust 1.90.0 and 1.100.0. Its worked-example
answers come from the pinned NIST corpus, not another Brynja backend.
Native x86-64 and Apple Silicon, emulated Linux AArch64 and RV64, and
Cortex-M compile checks have different evidence scopes. The previous
[Arm timing limitation](../docs/assurance/ghash-acceleration.md#arm-public-pmull-route)
remains unresolved.

The versioned candidate replay on 2026-11-24 passed the portable archive
check and all 52 runtime configurations: 12 Linux x86-64, 12 Linux AArch64
under QEMU, 16 Linux RV64 under QEMU, and 12 native Apple Silicon. Counts
include expected rejection and quarantine, not just successful constructors.
The four Linux-hosted checks have local `brynja-verify` records; the Mac
runner was executed separately.

No new production code, dependencies, GCM service or crates.io upload.
Candidate review, final checks and exact-commit GitHub approval precede tagging.
