# Brynja 0.24.19 Release Notes

Status: implementation candidate; exceptional pentest pending

## Summary

Complete portable MD5 is available in unpublished `brynja-legacy-md5` 0.1.0.
The facade advances to internal 0.24.19 without enabling or reexporting MD5.
This milestone selects zero crates for publication, including changed support
crates. No modern cryptographic implementation or external dependency changes.

## Deliverables

- RFC 1321 byte/arbitrary-bit one-shot and streaming APIs, MSB-first tails,
  little-endian words/digests, and low-64-bit message length padding.
- Checked u128 message accounting: crossing 2^64 is supported; values beyond
  u128::MAX are rejected before mutation as an explicit API representability cap.
- Sealed hardened state, consuming finalization, explicit declassification,
  typed secret output and complete secret-destination clearing on failure.
- Five mandatory source-owned clearing regions, without a schedule copy,
  first-party safe allocation-free no_std Rust and no new C or dependencies.
- Seven RFC examples, million-byte, partition/padding/bit-boundary tests,
  independent bit oracle, bounded malformed requests and external-package use.
- Source/mutation, owner-compiler, MSRV, no_std, Miri, ASan and Kani integration.
  Completed local checks are recorded separately in the pentest report.
- Refresh the Miri/sanitizer compiler to `nightly-2026-09-06`, exact Rust
  revision `f248f4038796913873f11ca65b1b901e311c8dae`, after the online tooling
  check. Stable Rust remains 1.98.1; no package dependency changes.

## Security and remaining work

MD5 is collision- and chosen-prefix-broken. It is not appropriate for new
security designs, signatures, certificates or password hashing. A raw digest
is not a MAC. Memory hardening does not repair MD5. Modern facade, generic-hash,
TLS, PKIX and FIPS graphs do not select this crate. Later legacy constructions
require their own typed admission; no HMAC-MD5 API is delivered here.

Ordinary output is public; hardened output requires an explicit classification.
Owned regions clear on Drop, cancellation, consuming error and recoverable
unwind. Registers, compiler copies/spills, caches, moves, caller copies, swap,
dumps, DMA, forget, abort and termination remain residual risks. No independent
cryptographic review, FIPS validation or CPU-backend admission is claimed.

MD5 remains **In progress** through frozen portable acceptance, SIMD work and
final-family disposition in v0.24.20–v0.24.23. Rust 1.90.0–1.98.1 compatibility
is retained; Kani uses its separately documented older verifier toolchain.

## Release conditions

Local candidate verification passed: complete repository gate, twelve stable
Rust lanes, bare-metal/platform compilation, official RFC vectors, independent
bit oracle, packaged consumer, MD5 Miri/ASan, u128 Kani proof, exact compiler
owner contracts, advisory and tooling-freshness checks. See the permanent
report for exact scope and exclusions. This is not independent review.

New crypto/secret ownership requires an exceptional pentest, then a complete
local release check, report commit, green GitHub/CodeQL and explicit owner
permission to tag. Candidate preparation does not tag, push or publish.

See [MD5 assurance](../docs/legacy-md5.md) and
[pentest report](../security/pentest/v0.24.19.md).
