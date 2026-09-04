# Brynja 0.24.15 Release Notes

Status: implementation complete; exceptional pentest required before tagging

## Summary

Brynja 0.24.15 implements `ParallelHash128`, `ParallelHash256`,
`ParallelHashXOF128`, and `ParallelHashXOF256` from NIST SP 800-185. The new
`brynja-hash-parallel` leaf is allocation-free `no_std` Rust. Its sequential
API uses a caller-owned workspace whose positive length is the exact `B`
parameter; its scheduling API exposes exact indexed leaf jobs and accepts
their typed results only in deterministic standard order.

The separate zero-third-party-dependency `brynja-hash-parallel-std` package automates the
same jobs with bounded native threads, cooperative cancellation, worker-panic
containment, and fail-closed output. It is absent from Brynja's default graph,
main facade, bare-metal path, and FIPS boundary.

This completes the four ParallelHash identities. The wider SP 800-185 family
remains In progress until portable combined acceptance at v0.24.16 and final
cross-backend/parallel acceptance at v0.24.17. No independent cryptographic
verification or FIPS 140-3 validation is claimed.

## Deliverables

- Apply exact `left_encode(B)`, 256/512-bit SHAKE leaf values,
  `right_encode(n)`, fixed `right_encode(L)` or XOF `right_encode(0)`, the
  `ParallelHash` function name, and arbitrary-bit customization.
- Support empty input, `B = 1`, partial final leaves, multi-leaf streaming,
  canonical arbitrary-bit final input, fixed arbitrary-bit output, and
  incremental XOF output for both strengths.
- Reuse the hardened cSHAKE owner for leaf and final nodes. Sequential scratch,
  leaf values, outer state, counters, partial input, reader state, and typed
  secret output are cleared through Brynja's compiler-resistant boundary.
- Provide immutable plans, exact indexed leaf jobs, caller-owned leaf result
  storage, and collectors lifetime-bound to the exact issuing plan that reject
  missing, repeated, reordered, cross-plan, differently sized, or differently
  parameterized results and then fail closed permanently.
- Provide a separate native executor with a positive bounded worker count,
  fallible bounded allocation, deterministic join/merge, cooperative
  cancellation, worker-panic containment, byte and arbitrary-bit API parity,
  complete temporary leaf clearing, and unchanged output on pre-output failure.
- Reexport the portable family from `brynja-crypto` and `brynja`; do not
  reexport or otherwise activate the `std` executor.

## Verification

- All six official NIST ParallelHash examples and all six official
  ParallelHashXOF examples pass at both strengths, `B = 8`/`12`, empty and
  `Parallel Data` customization, and fixed 256/512-bit output.
- Streaming partitions, one-shot operation, caller-scheduled leaf execution,
  and native executor worker counts produce identical output.
- Empty input has exactly zero leaves; `B = 1` is accepted; zero `B` is rejected
  before construction; arbitrary-bit final input/output remains canonical.
- Reordered results permanently quarantine the collector, cancellation leaves
  caller output unchanged, and typed leaf/output owners clear their complete
  caller storage when dropped.
- Any error after sequential or scheduled state mutation permanently
  quarantines and clears that state; callers cannot retry a partially advanced
  construction.
- The portable crate contains no allocation, native code, FFI, global mutable
  state, or third-party dependency. The host adapter contains no cryptographic
  implementation and depends only on the portable leaf plus Brynja's core
  compiler-resistant clearing boundary.
- The complete repository gate, no-default/all-feature graph checks, package
  archives, Rust 1.90.0/1.98.1 compilation, Clippy, documentation, Miri,
  sanitizer, proof, mutation, and independent differential evidence must pass
  before the report-bearing release commit.

## Security And Residual Limits

- Ordinary APIs classify messages and output as public. Secret-bearing use
  requires the distinct hardened states and typed secret output.
- The no_std scheduling API binds every job, result, and collector to the exact
  issuing plan and verifies order and public plan parameters. Callers remain
  responsible for bounding their own scheduler resources.
- Native cancellation is cooperative. Forced termination, abort, power loss,
  forgotten owners, registers, caches, compiler-created copies, swap, dumps,
  DMA, physical remnants, and caller-owned copies remain outside portable
  erasure guarantees.
- No CPU backend is newly admitted. Parallel leaf concurrency is separate from
  Keccak instruction acceleration.
- Brynja remains pre-1.0 and has no usable TLS connection or certificate
  validation engine.

## Authority

The implementation is bound to the pinned final NIST SP 800-185 and FIPS 202
documents. Official examples come from NIST's ParallelHash and ParallelHashXOF
sample documents, whose retrieved SHA-256 identities are
`4e1a6ff692f68bdebabbbcbf0596f6d35ec39636c9ab71dc434f5d47c5634d80`
and `c9d460ea1c8fcc8032f043fe0861b248fae1522f19c3d14935ccbb0a693e4ca6`.
The lifecycle monitor records the announced SP 800-185 revision separately;
future upstream changes cannot silently alter this implementation.

## Release Process

Version 0.24.15 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates for crates.io publication.
The new cryptographic construction, secret-bearing scheduling boundary, and
native worker adapter trigger an exceptional pentest. After a clean retest,
the permanent report, complete local gate, and green hosted GitHub and CodeQL
are required before the signed tag.
