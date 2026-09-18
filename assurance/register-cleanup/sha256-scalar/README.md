# Hardened scalar SHA-224/256 cleanup

This development fixture includes the actual private scalar compressor used by
both hardened SHA-224 and SHA-256. It does not change release gates or qualify
the complete high-level API. Ordinary public hashing is unchanged.

The baseline x86-64/little-endian AArch64 ports need no crypto/SIMD instruction
feature. Four fixed pointers enter one opaque block: 64-byte big-endian state,
128-byte input, 640-byte owned scratch and the public 64-word round table. Only
the first 32 state bytes and 64 input bytes participate. Schedule bytes 0..256
and working-state bytes 256..288 are explicitly owned storage, not compiler
spills. All 64 rounds and feed-forward stay in the stack/call-free boundary.
The entire scratch region and working registers clear before normal return.
The surrounding owner retains its existing compression-scratch destruction.

Run `python3 assurance/register-cleanup/check_sha256_scalar.py` for:

- Thirty Rust 1.90.0/1.98.1 debug/release fixture compiler checks spanning Linux,
  Apple, Android and Windows; eight actual no-default-feature crate builds.
  Windows/Apple checks are cross-compilation, not native qualification.
- Eight native Linux x86/QEMU Arm runtime configurations, each with 1,024
  independent state/block pairs, 32 unaligned placements, canaries, input and
  upper-state preservation, complete scratch erasure and immediate
  return-register snapshots. The reference independently derives constants
  from prime cube roots and checks the published SHA-256 `abc` digest.
- Sixteen independent guard-page combinations, with read-only input/table.
  Thirteen x86/fifteen Arm compiled controls/mutants per configuration test
  individually missing wipes after poisoning, bad rounds/rotations/schedule/
  feed-forward, missing scratch cleanup and an uncleared final scratch word.
  Poison-before-wipe positive controls pass.
- Emitted-code mutations reject pre-boundary loads, stack spills and
  post-cleanup reloads. The ordinary compressor included only for its constants
  keeps the repository's existing `chunks_exact_to_as_chunks` style allowance;
  the fixture and new boundary otherwise pass strict Clippy.

The observer runs only under Linux SysV/AAPCS64. Incoming ABI-preserved caller
registers are restored, not erased. Other targets and Miri/Kani keep the safe
Rust compression model, without this register claim. High-level copies, input
packing, padding, output, owner moves, interruption, abort and platform storage
remain outside this narrow normal-return guarantee.

The local release comparison against `62efbfd9` used five alternating runs of
1,024 `HardenedSha256` update/finalize-secret operations per message size, with
digest and output-destruction assertions. Median new/old elapsed ratios were
1.5773 (64 bytes), 1.2684 (1 KiB), and 1.2755 (16 KiB). The explicit owned
working storage and cleanup have a real scalar cost. These are diagnostic
measurements, not a general performance guarantee; existing accelerated kernels
are not replaced by this path.
