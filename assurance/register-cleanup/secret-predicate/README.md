# Borrowed predicate development evidence

This unpublished fixture imports the actual private core helper. Linux x86-64
and AArch64 observers snapshot its working register, Boolean return and flags
immediately after the call. All 65,536 input/mask pairs are checked, including
input preservation; read-only guarded pages enforce exact byte reads.

Run `python3 assurance/register-cleanup/check_secret_predicate.py` at the root.
The driver checks Rust 1.90/1.98 debug/release output, actual core artifacts,
native x86 and emulated Arm behavior, positive poison controls, omitted-cleanup
and algorithm mutants, and emitted boundary corruptions. Apple, Windows and
Android coverage is compilation-only. No release-gate step is added.

The result intentionally discloses a predicate. Arbitrary repeated masks can
reveal the byte. The guarantee covers only this helper's normal-return secret
working register and flags, not caller copies/spills or interruption snapshots.
