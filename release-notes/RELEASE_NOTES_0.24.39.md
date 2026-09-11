# Brynja v0.24.39

Status: implemented; focused development verification passed, exceptional pentest
and release qualification pending.

Adds default-off `brynja_hash_tuple::execution` APIs for all four TupleHash and
TupleHashXOF identities. Separate public/unkeyed and hardened owners retain exact
tuple framing, arbitrary-bit items/customization/output, affine item writers,
consuming fixed finalizers and exclusively borrowed incremental readers.
Portable, preferred and required authority selection is explicit. A supplied
backend failure never silently falls back.

The implementation composes the existing hardened cSHAKE owners. No new unsafe
Rust, third-party dependency or default acceleration is introduced. All internal
metadata and bounded packing/output staging are cleared on normal completion,
errors, cancellation and recoverable unwind. Public errors preserve output;
secret errors erase destinations and successful secret output stays typed.
Forgetting a writer or reader cannot reopen its parent state.

See the [API guide and limitations](../docs/tuplehash-accelerated-execution.md).
Owned-memory clearing is not a guarantee for registers, compiler copies, spills,
caches, swap, dumps, DMA, abort, forced termination or forgotten owners. Caller
inputs and copies remain caller responsibilities. Owners are movable and not
locked memory. Thread-affine types do not prevent OS CPU migration.

Development checks include all twelve official NIST examples, 256 independent
arbitrary-bit cases per selected route, existing portable API comparisons,
secret/public XOF partitions, authority loss mid-item, ownership rejections,
compiled cleanup and algorithm mutants, and MIR/LLVM/assembly inspection.
Native AMD AVX2 and emulated Arm execution are development checks, not a
substitute for fresh three-platform TupleHash collection after pentest.

Exceptional owner pentest, native evidence review, final scoped release checks
and green GitHub/CodeQL remain mandatory before tagging. This is neither
independent cryptographic verification nor FIPS validation.

Focused development results:

- 20 unit/integration/vector tests and 55 compile-fail ownership doctests;
  strict scoped Clippy and Rust 1.90 bare-metal `no_std` compilation.
- 268 official/independent oracle cases per portable, absent-preferred, native
  AMD AVX2 static/preferred and emulated Arm hosted/static/preferred route.
- Packaged consumer: 68 ownership/classification rejections, 20 compiled
  debug/release cleanup mutants and eight compiled algorithm mutants.
- 141 semantic execution-policy and 87 native-format/schema regressions.
- MIR/LLVM/assembly owned-region clearing on Rust 1.90.0 and 1.98.1 for x86-64
  and AArch64; four focused Miri owner tests and the writer-unwind/forgotten-reader
  lifecycle test; native AVX2 AddressSanitizer oracle campaign.
- Both existing TupleHash Kani arithmetic harnesses passed. These prove the
  selected bounds, not the complete cryptographic algorithm.

This internal milestone publishes no crates. All release selections remain
`publish = false`; the next crates.io checkpoint remains v0.25.2.
