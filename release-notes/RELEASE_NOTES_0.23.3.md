# Brynja 0.23.3 Release Notes

Status: final candidate; exceptional pentest PASS and native disposition complete; hosted verification and internal tag pending; no crates.io publication

Brynja 0.23.3 extends its optional CPU boundary across all six complete SHA-2
algorithm identities while keeping portable scalar behavior authoritative.

## Added

- SHA-224 forced-backend one-shot and streaming APIs over the exact existing
  SHA-256-family compression sessions.
- Static, thread-bound, caller-owned AArch64 SHA-512 and RV64 Zknh SHA-512
  sessions with direct startup KATs, health generations, permanent quarantine,
  exact 128-byte compression, and closed failures.
- Forced backend APIs for SHA-384, SHA-512, SHA-512/224, and SHA-512/256 over
  their unchanged distinct IV, padding, output, and exhaustion rules.
- Complete-family std reporting and scalar fallback. Unadmitted AArch64
  SHA-512 capability remains observational; RISC-V automatic activation stays
  disabled.
- An explicit x86_64 SHA-512 scalar-only decision. AVX2 and AVX-512 presence
  alone does not establish an acceptable single-stream backend.

## Verification

- Differential execution of every SHA-2 identity over empty, padding-edge,
  block-edge, multi-block, and irregularly chunked inputs through forced
  AArch64 and RISC-V candidates under QEMU.
- Direct SHA-512 startup KAT success and corrupted-answer quarantine tests,
  wrong-architecture rejection, health reporting, and ordinary-build
  non-admission.
- Rust 1.90.0 and 1.97.1 emitted-code checks for RV64 SHA-512 instructions,
  plus AArch64 SHA-512 and existing SHA-256-family instruction checks.
- Exact hash-bound CPU source inventory, five candidate identities, zero
  admitted backends, one x86 scalar-only decision, and adversarial policy
  fixtures.
- Exact-commit native candidate observations on local AMD, observed-feature
  AWS Intel, Apple M2 and AWS Arm. Both Arm lanes execute every SHA-2 identity
  and emit SHA-512 instructions; the registered RISC-V host remains
  non-qualifying and QEMU-only.

QEMU and compiler output are supplemental evidence. Qualifying native
SHA-512-family correctness, performance, CPU-migration, and side-channel
evidence remains required before any backend can be admitted.

## Security Boundaries

All ISA code is first-party Rust. No C or C++ module, foreign ABI, external
assembly source, build script, third-party detector, allocation, I/O, or global
backend registry is introduced. The default SHA-2 feature set remains portable
`no_std` scalar code, and neither the CPU package nor std adapter enters the
modern facade, protocol engines, or future FIPS module automatically.

All five candidates remain unadmitted. This release makes no register, spill,
stack, cache, timing, independent-review, or FIPS 140-3 validation claim.

## Release Process

Version 0.23.3 is an internal milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates.io packages. The new low-level
cryptographic kernels triggered an exceptional pentest. The assessment of
exact signed candidate `61d8e829b54a1ac87d38c6bc4509e4e7a43e3ef0`
records `PASS`/`PASS` with zero open findings. Its native disposition keeps all
five candidates unadmitted. The full local gate, hosted GitHub, and CodeQL must
be green before explicit tag authorization.
