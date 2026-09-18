# Hardened MD5 transfer checks

Development checks of the actual private `cpu/transfer.rs`, not a replacement
implementation or complete native qualification. Run from the repository root:

```sh
python3 assurance/register-cleanup/check_transfer.py --family md5 --arm
```

Four opaque scalar specializations pack a lane's 16-byte state or 64-byte block,
commit a state, and copy the 128-byte inter-block result. Eight packed lanes are
retained; Arm compression uses four active lanes. Invalid safe-entry indices
reject before mutation. EAX (x86) or X4 (Arm) is the only secret-bearing working
register; all working registers clear before normal return. No additional ISA
requirement, public API, authority or release-gate mechanism is introduced.

The fixture's scratch mirror models layout only; it is not a clearing owner.
Production retains its existing clearing storage and failure guards. Eight
native x86/QEMU Arm compiler/profile runs each cover 800 mapping and unaligned
cases, 28 guard-page placements with read-only sources, and nine positive
controls/mutants. The tests reject omitted erasure, poisoned erasure, missing
loads/stores, truncated copies, wrong packed stride and wrong lane selection.
The driver also checks thirty emitted-code configurations, including Windows
and Apple targets, and eight builds of the actual production crate. Windows
and Apple cross-compilation is not native execution.

Miri tests only the safe model. Neither these tests nor accelerated kernel
cleanup qualifies portable compression, scalar final padding, high-level output
copies, owner moves, pre-existing caller registers, or asynchronous interruption.
Performance qualification and F1 remain open; no independent verification or
FIPS claim follows from this development checkpoint.
