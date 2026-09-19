# Borrowed secret-byte mask development evidence

This unpublished fixture compiles the actual private core mask implementation,
not a second algorithm. Run `python3 assurance/register-cleanup/check_secret_mask.py`
from the repository root. This is not an added release gate.

The driver checks both Rust endpoints, debug/release, native Linux x86 and
emulated Linux Arm. Apple, Android and Windows are compilation-only rows. It
also inspects the actual core crate assembly for the Linux rows. An immediate
assembly observer checks the working register before Rust resumes, over 196,608
input/mask combinations. Protected pages catch widened accesses at both edges.
Compiled missing-operation/store/wipe mutants must fail at runtime; poisoned
positive controls must pass. Emitted-code mutations reject escaping calls,
spills/reloads and early returns.

Only the opaque one-byte boundary has this normal-return claim. Public masks
and the pointer are not secrets. Compiler-created caller copies, spills, OS
interruption snapshots and full API return state remain separate obligations.
No independent, native-platform, timing or FIPS qualification is implied.
