# SHA-512-family batch transfer probe

Development-only checks of the actual private production `transfer.rs`, not
native qualification or a complete hardened hash API cleanup claim.

The batch workspace imports state/block words and commits output through
stack-free opaque transposition functions. Only pointers and public shape/endian
parameters cross the Rust boundary. Secret words remain in RAX on x86-64 or X4
on little-endian AArch64; the working registers are erased before return. The
fixed layout contains four lanes of eight-byte words, with two active lanes for
NEON and four for AVX2. No dedicated SHA512 instruction or new ISA requirement
is introduced. The post-compression health/counter check still precedes output
commit, and failure preserves caller state.

Run from the repository root:

```sh
python3 assurance/register-cleanup/check_transfer.py --family sha512 --arm
```

The requirements and boundary limitations match the
[SHA-224/256 transfer probe](../sha256-transfer/README.md). The shared driver
checks 30 endpoint compiler/target/profile configurations and eight actual
CPU-crate builds. Eight native Linux x86/emulated Arm configurations each cover:

- Three layouts, widths 0–4, three endian selectors and 32 unaligned offsets:
  1,440 scalar-reference comparisons with source/destination canaries.
- Twelve guard-page placements with read-only input, and immediate return
  observations of the only secret-bearing working register.
- Ten original/poisoned/broken controls. Omitted or incorrect clearing, input
  loading, output stores and endian conversion must fail execution. Separate
  32-bit load/store/byte-swap mutants catch upper-word truncation.
- Injected spills and out-of-boundary secret loads rejected by the emitted-code
  checker. Pointer/stack marshaling is inspected separately from computation.

The in-crate `transfer_tests` covers the actual byte/word wrappers, native-endian
state mapping, schedule/inactive capacity and independently chosen output.
Miri checks the safe Rust model; it does not execute assembly. Windows/Apple
cross-compilation is not native execution evidence.

A local diagnostic comparison against `f33d1934` used the existing hardened
batch benchmark, Rust 1.98.1 release, AVX2, three alternating before/after runs
and sixteen full-width balanced SHA-512-family workloads (4/16 KiB). Median
selected-route elapsed time increased about 4.4% (range 3.8–5.1%). Actual AVX2
execution, output comparison and cleanup checks passed in both revisions.
This is the measured cleanup cost on that host, not a performance guarantee
or a claim about sparse/short inputs, native Arm or Windows.

Caller buffers, pre-existing caller registers, interrupt snapshots, portable
compression and higher-level framing/owner copies remain outside this narrow
normal-return boundary. F1 remains open; no release gate or native approval
has changed.
