# Scalar SHA-1 normal-return cleanup

This development fixture includes the actual private scalar compressor. It
does not change release gates or certify the complete high-level API. SHA-1
remains collision-broken and unsuitable for new cryptographic designs.

The x86-64 and little-endian AArch64 ports use baseline integer instructions;
no SHA/SIMD feature or execution authority is acquired. Three fixed byte-array
pointers enter one opaque block: 20-byte big-endian state, read-only 64-byte
input, and exclusive 320-byte schedule. The schedule is completely overwritten
before use and cleared before return. The 80 rounds and feed-forward do not
use the stack or call other functions. All working registers are erased;
incoming ABI-preserved caller registers are restored, not erased. The outer
owner still clears block/schedule/buffered storage afterward.

`python3 assurance/register-cleanup/check_sha1_scalar.py` checks:

- Rust 1.90.0/1.98.1, debug/release, Linux, Apple, Android and Windows emitted
  assembly: 30 fixture builds and eight actual default-feature-disabled crate
  builds. Apple/Windows results are cross-compilation, not native evidence.
- Eight native Linux x86/emulated Arm configurations, each with 1,024 arbitrary
  state/block pairs (including zero/all-one), 32 unaligned placements, output
  canaries, input preservation, schedule clearing and immediate return-register
  snapshots. The independent reference is cross-checked with published `abc`.
- Eight independent guard-page placements for the three operands; input pages
  are read-only. Each wipe is independently removed after poisoning registers;
  positive poison-before-wipe controls pass. Round-count, rotate, schedule,
  feed-forward and partial/missing schedule-clear mutants fail: 15 x86 and
  17 Arm controls/mutants per configuration.
- Emitted-code mutations for loads outside the opaque block, spills and
  post-cleanup reloads. Compiler-generated code may marshal pointers or restore
  incoming callee-preserved registers, but may not load secret operands.

The observer executes only on Linux SysV/AAPCS64. Miri/Kani and other targets
retain the safe Rust model without this machine-register guarantee. These
checks do not prove interruption/abort cleanup, erase caller state or cover
high-level framing, padding, output copies or moved owner copies.

A diagnostic release comparison against `13569e6a` used 1,024 high-level
`HardenedSha1::digest_secret` calls per size over five alternating runs, checking
the digest and output-owner destruction. Median new/old elapsed-time ratios
were 1.0095 (64 bytes), 1.0199 (1 KiB), and 1.0121 (16 KiB). This is not a
performance guarantee or native qualification of other machines.
