# Borrowed bit-XOR development evidence

This unpublished fixture imports the actual private core helper. It observes
working registers immediately after return on Linux x86-64 and AArch64, checks
104,448 valid source/range/destination combinations, and tests all pairs of
protected source/destination page edges with a read-only source.

Run `python3 assurance/register-cleanup/check_secret_xor.py` from the repository
root. The development driver checks Rust 1.90/1.98 debug/release output, native
x86 and QEMU Arm execution, real core artifacts, compiled omission/poison
controls and emitted spill/reload/early-return mutations. Apple, Windows and
Android checks are compilation-only. It adds no release-gate step.

This verifies this helper's normal-return working-register boundary, not source
ownership, caller copies, arbitrary spills, abort or interruption snapshots.
The checked public adapter is separately exercised by core tests and Miri.
