# v0.28.2 review candidate — opt-in GHASH acceleration

Enable `ghash-runtime-execution` on the facade or the crypto crate to use
`Ghash::new_with_backend`. The existing constructor remains portable, even
with all features enabled. Linux x86_64 can select PCLMUL; little-endian
AArch64 Linux and macOS can select PMULL; Linux RV64 can select scalar Zbc.
Zbkc alone and RISC-V vector crypto do not select a public native route.

Only missing support allows portable fallback in prefer mode. Require mode
reports unavailability, and both modes refuse a failed startup self-test
without changing the caller's workspace. GHASH does not select AES or return
an authentication tag.

The [assurance record](../docs/assurance/ghash-acceleration.md) documents
native, emulated, and archive-consumer coverage and preserves the inconclusive
AWS Arm timing control. This is not side-channel qualification. The Rust
minimum remains 1.90.0 and the tested upper endpoint is 1.100.0.

Internal milestone, zero packages selected for upload. The initial [scoped
pentest and dispositions](../docs/assurance/ghash-acceleration-review.md)
cover v0.28.1 through `3373a671`. A retest of the fixes, final checks and
exact-commit GitHub/CodeQL approval are pending. No new timing campaign is
required by the release gate.
