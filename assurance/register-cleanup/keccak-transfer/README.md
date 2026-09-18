# Keccak batch transfer probe

Development-only checks of the actual private production `transfer.rs`, not
native qualification or a complete hardened sponge API cleanup claim.

The workspace imports and commits 25-word Keccak states through two opaque
transposition functions. Each operand has a fixed 800-byte extent: four states
of 200 bytes versus 25 packed rows of 32 bytes. Two lanes are active with NEON,
four with AVX2. Canonical little-endian byte states and native words share the
same mapping on the supported targets; no byte reversal is needed.

Only pointers and public width cross the Rust boundary. RAX on x86-64 or X4
on little-endian AArch64 holds secret words; it and the public working registers
are erased before return. The block uses no stack, calls or vector instructions.
The existing health/counter check remains between permutation and output commit.
No ISA prerequisite, public API, authority or quarantine rule has changed.

Run from the repository root:

```sh
python3 assurance/register-cleanup/check_transfer.py --family keccak --arm
```

The requirements and general limitations match the
[SHA-224/256 transfer probe](../sha256-transfer/README.md). Thirty compiler/
target/profile configurations inspect emitted code; eight also inspect the real
CPU crate. Eight native Linux x86/emulated Arm configurations each cover:

- Both layouts, widths 0–4 and 32 unaligned offsets: 320 scalar-reference
  comparisons with unchanged inputs and destination canaries.
- Eight guard-page placements with read-only input; assembly memory accesses
  are not internally instrumented by AddressSanitizer.
- Immediate return-register observations, seeded before execution. Ten
  original/poisoned/broken controls test missing or incorrect clearing, omitted
  loads/stores, truncated word accesses, wrong row count and wrong state stride.
- Emitted-code mutations introducing spills or secret loads outside the opaque
  boundary. Pointer/stack marshaling is inspected separately from computation.

In-crate tests independently check byte/word wrappers, inactive capacity, clearing
of other workspace regions and distinct output mappings. Existing lifecycle
tests cover revocation, overflow and unwind with caller-state preservation.
Miri exercises the safe model, not the assembly. Windows/Apple cross-compilation
does not establish native execution qualification.

A local diagnostic benchmark against `b4f33b0c` used Rust 1.98.1 release and
AVX2, three alternating before/after runs and sixteen balanced full-width
SHA-3/SHAKE/cSHAKE workloads (4/16 KiB). Median elapsed time increased about
3.5% (range 1.5–11.9%). Actual AVX2 execution, correct output and cleanup were
checked in both revisions. These host-local noisy measurements are not a
performance guarantee or qualification of other platforms/workload shapes.

Caller buffers, pre-existing caller registers, interrupt snapshots, portable
permutation and higher-level absorption/squeeze/owner copies remain outside
this narrow normal-return boundary. F1 remains open. No release gate, native
approval, independent verification or FIPS claim has changed.
