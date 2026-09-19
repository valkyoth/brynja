# Private secret-initialization transfer checks

Development fixture for the actual core `SecretRegionInitialization::write`
copy boundary and the additive `copy_secret_region` borrowed transfer API.
The latter retains caller-owned cleanup and rejects unequal lengths before
mutation. No release gate is introduced or changed.

Run `python3 assurance/register-cleanup/check_secret_copy.py` from the repository
root. It checks Rust 1.90.0/1.98.1 debug/release compiler output, then executes
Linux x86-64 natively and Linux AArch64 under QEMU. Apple, Android and Windows
builds are compiler checks, not native platform qualification.

The fixture exercises 8,512 length/alignment combinations, preserved source and
destination canaries, independent guarded source/destination placements,
read-only sources, empty null-pointer transfers and rejected length mismatches.
Immediate post-return observers check all working registers. Poisoned positive
controls must pass; individually omitted wipes and corrupted word/tail copies
must fail at runtime. Assembly mutations check spills and post-cleanup loads.

The normal-return guarantee covers this copy's own working registers and lack
of secret stack spills on the checked baseline x86-64/little-endian Arm ports.
It does not erase source storage, pre-existing caller registers, higher-level
framing, moved owners, interruption snapshots or platform storage. Other-target
and Miri/Kani safe models do not establish this assembly guarantee. F1 remains
open for the wider caller audit and remaining architecture coverage.
