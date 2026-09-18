# Hardened scalar Keccak cleanup

This development fixture includes the actual private baseline Keccak-f[1600]
permutation used by hardened SHA-3, SHAKE and cSHAKE, and their shared higher
constructions. It does not change release gates or qualify complete public APIs.
Ordinary public permutation code and accelerated kernels are unchanged.

The x86-64/little-endian AArch64 ports need no SIMD or crypto feature. Five fixed
pointers enter one opaque block: 200-byte little-endian state, 40-byte columns,
40-byte theta deltas, 200-byte rearranged lanes and the public 24-word table.
All 24 theta/rho/pi/chi/iota rounds operate inside that stack/call-free block.
Offsets and branches depend only on public loop counters. All three scratch
arrays clear inside the block before register erasure. The surrounding owner
also retains its existing compiler-resistant scratch clearing call.

Run `python3 assurance/register-cleanup/check_keccak_scalar.py` for:

- Thirty Rust 1.90.0/1.98.1 debug/release fixture compiler checks spanning Linux,
  Apple, Android and Windows, plus eight actual no-default-feature crate builds.
  Apple/Windows are cross-compilation checks, not native qualification.
- Eight Linux native x86/QEMU Arm runtime configurations. Each covers 1,024
  independent states including zero/all-one states, 32 unaligned placements,
  canaries, complete scratch erasure and immediate return-register snapshots.
  The separate coordinate oracle generates rho/pi and round constants via
  recurrence/LFSR rather than importing the implementation's tables; it is
  cross-checked against the Keccak zero-state known answer.
- Thirty-two independent guard-page placements for all five operands, with
  read-only constants and inaccessible neighbors. These matter because ASan
  cannot instrument accesses inside inline assembly.
- Seventeen x86/nineteen Arm compiled controls/mutants per configuration.
  Poison-before-wipe positives must pass; each removed register wipe, each
  omitted scratch-array wipe, partial scratch erasure and corrupted round
  count/theta/rho/pi/chi/iota must fail in execution, not just compilation.
  Emitted-code mutations reject pre-boundary loads, stack spills and
  post-cleanup reloads.

The immediate observer uses Linux SysV/AAPCS64. It samples RAX/RCX/RDX/R10/R11
or X4-X10; the Arm boundary also resets condition flags. ABI-preserved incoming
caller registers are restored, not erased. Other targets and Miri/Kani keep the
existing safe Rust model without this register claim. High-level input/output,
framing, moved owners, interruption, abort, and platform storage remain outside
this narrow normal-return guarantee. F1 remains open.

The local release comparison against `3fba51fd` used five alternating runs of
1,024 `HardenedSha3_256` update/finalize-secret operations per message size,
asserting the digest and output destruction. Median new/old elapsed ratios were
0.6572 (136 bytes), 0.6122 (1 KiB), and 0.6212 (16 KiB). These local diagnostic
measurements are not a general performance guarantee or a native Arm benchmark.
