# Hardened scalar SHA-512-family cleanup

This development fixture includes the actual private scalar compressor shared
by hardened SHA-384, SHA-512, SHA-512/224, SHA-512/256 and general SHA-512/t.
It does not change release gates or qualify the complete high-level API.
Ordinary public hashing is unchanged.

The baseline x86-64/little-endian AArch64 ports need no crypto/SIMD instruction
feature. Four fixed pointers enter one opaque block: 64-byte big-endian state,
128-byte input, 640-byte owned scratch and the public 80-word round table.
Scratch bytes 0..128 hold a 16-word rolling schedule; bytes 128..192 hold the
eight working words. This leaves the existing owner layout unchanged without
compiler-generated secret stack storage. All 80 rounds, feed-forward and
erasure of all 640 scratch bytes stay inside the stack/call-free boundary.
Working registers clear before normal return. The surrounding owner retains
its existing compression-scratch destruction.

Run `python3 assurance/register-cleanup/check_sha512_scalar.py` for:

- Thirty Rust 1.90.0/1.98.1 debug/release fixture compiler checks spanning Linux,
  Apple, Android and Windows; eight actual no-default-feature crate builds.
  Windows/Apple checks are cross-compilation, not native qualification.
- Eight native Linux x86/QEMU Arm runtime configurations, each with 1,024
  independent state/block pairs, 32 unaligned placements, canaries, preserved
  input, complete scratch erasure and immediate return-register snapshots.
  The reference uses a separate full 80-word schedule, not the rolling driver;
  integer prime cube roots reproduce its constants independently of production.
  It also checks the published SHA-512 `abc` digest.
- Sixteen independent guard-page combinations, with read-only input/table.
  Sixteen x86/seventeen Arm compiled controls/mutants per configuration test
  individually missing register wipes after poisoning, bad round count,
  rotations, schedule offsets, ring masks, skipped schedule expansion,
  feed-forward and missing/partial scratch erasure. Poison-before-wipe positive
  controls pass. Mutants must fail in execution, not during compilation.
- Emitted-code mutations reject pre-boundary loads, stack spills and
  post-cleanup reloads. The actual-crate checks distinguish narrow/wide scalar
  symbols; adding this boundary must not make the SHA-256 inspector ambiguous.
  The ordinary compressor included only for its constants keeps the existing
  `chunks_exact_to_as_chunks` style allowance; the new code passes scoped Clippy.

The observer runs only under Linux SysV/AAPCS64. Incoming ABI-preserved caller
registers are restored, not erased. Other targets and Miri/Kani keep the safe
Rust compression model without this register claim. High-level copies, input
packing, padding, output, owner moves, interruption, abort and platform storage
remain outside this narrow normal-return guarantee. F1 remains open.

The local release comparison against `40cdf699` used five alternating runs of
1,024 `HardenedSha512` update/finalize-secret operations per message size, with
digest and output-destruction assertions. Median new/old elapsed ratios were
1.3646 (128 bytes), 1.0837 (1 KiB), and 1.0979 (16 KiB). This scalar cleanup
cost is real; these diagnostic measurements are not a general performance
guarantee and existing accelerated kernels are not replaced by this path.
