# SHA-224/256 batch transfer probe

Development-only checks of the actual private production `transfer.rs`, not
native qualification or a complete hardened hash API cleanup claim.

The batch workspace now imports state/block words and commits output through
stack-free opaque transposition functions. Rust receives only pointers and
public shape/endian parameters. The one secret-bearing register (RAX on x86-64,
X4 on AArch64) and public scratch registers are erased before return. No new
SIMD or hardware prerequisite is introduced. State/block layout, authority,
quarantine and the health/counter check before output commit are unchanged.
Miri, Kani and unsupported targets retain the safe Rust transfer model; they
are not covered by the native register-erasure claim.

Run from the repository root:

```sh
python3 assurance/register-cleanup/check_transfer.py --arm
```

Requirements: Rust 1.90.0 and 1.98.1 with the targets named by the driver,
QEMU AArch64 and a native Linux x86-64 host. Nothing is downloaded by the driver.
It uses disposable copies for source mutations and leaves production unchanged.

The driver checks 30 debug/release compiler/target combinations, including
Linux, Apple, Android and Windows assembly, plus eight builds of the actual
CPU crate. Windows and Apple builds are cross-compiled, not executed natively.
Eight native x86/emulated Arm compiler/profile configurations each check:

- Three distinct layouts, widths 0–8, three public endian selectors and 32
  unaligned offsets: 2,592 scalar-reference comparisons with canaries.
- Twelve guard-page placements, including read-only inputs. Guard pages check
  assembly accesses that sanitizers cannot instrument internally.
- Immediate return-register capture, seeded before the call. A poisoned-but-
  cleared positive control passes; omitted/incorrect erasure fails. Omitted
  endian conversion, input loads and output writes also fail real execution.
- Emitted-code mutants introducing secret loads or spills around the opaque
  boundary are rejected. Compiler-generated pointer/stack marshaling is checked
  separately from the stack-free computation and exact erasure sequence.

The in-crate `transfer_tests` independently tests byte/word wrappers, active and
inactive lanes, schedule clearing and output mapping. Existing lifecycle tests
cover revocation, overflow and unwind before caller output is committed.

This does not erase caller buffers, pre-existing caller registers, upper vector
state, interrupt snapshots, or high-level framing/owner copies. It does not
establish native Windows/Arm qualification, independent review, constant-time
machine validation, military suitability or FIPS validation. F1 remains open.
