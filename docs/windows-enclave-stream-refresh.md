# Windows accelerated streaming image refresh

The October 4 development refresh rebuilt the separate SHA-NI SHA-224/256 and
AVX2 SHA-3/SHAKE/cSHAKE streaming images with the current register-clearing
wrapper. These are not the multibuffer images covered by the earlier SIMD
refresh. See the [hash-bound observations](../assurance/windows-protection-observations/stream-sha-refresh-20261004.json).

| Check | SHA-NI SHA-2 | AVX2 SHA-3 |
| --- | --- | --- |
| Component tests | 9 | 11 |
| Separate resident tests | 4 | Not separately rerun |
| Compiled Rust worker mutants rejected | 9 | 9 |
| Compiled baseline C gate/entry mutants rejected | 19 | 18 |
| Native VBS calls / digest comparisons | 151 / 21 | 419 / 57 |
| Host cases per debug/release profile | 46 | 1,028 |
| Lifecycle tests per profile | 32 passed, 7 ignored | 45 passed, 11 ignored |
| Scoped Windows Clippy | PASS | PASS |

The saved build-source and generated-artifact hashes reconcile with the local
checkout. Import preparation reproduced byte-for-byte. Both signed images
contain the exact reviewed 392-byte `PublicLockedFrame`, bound using the same
previously mutation-tested MASM object. This binds the wrapper, not the semantics
of every linked caller, callee or spill. The campaigns use Rust 1.98.1 on the
local Windows 11 x64 VBS development VM, build 26300.

The first SHA-3 mutation run failed when the linker could not reopen its output
(`LNK1104`). The failed logs remain saved. The unchanged complete suite passed in
a fresh directory; no test was skipped, weakened or counted from the failed run.
The specific cause of that file-open failure has not been established.

Signing remains development-only; temporary signing keys were removed and the
SDK compatibility warning retained. Positive host tests use internal development
transport. Public production constructors reject these test signatures.
Historical scalar images serve only as rejection controls: those errors alone
do not isolate their rejection reason, and do not refresh scalar qualification.
Ignored lifecycle cases are not counted as executed tests.

This is not independent review, production signing, Windows ARM64 coverage,
dedicated x86 SHA512 execution or whole-image spill/dump qualification. The saved
KMAC and TupleHash streaming images still need refresh, as do any other affected
images not yet reconciled. Release-gate policy is unchanged.

Raw builds, signed images, test binaries and logs are retained outside `target/`
in `release-reports/windows-local-20261004/`, under `sha2-stream-cleanup`,
`sha3-stream-cleanup-retry`, their `*-stream-cleanup-admitted` and
`*-stream-cleanup-host` directories. `verify_stream_cleanup.py` reproduces the
committed observation from these saved artifacts and checks current source hashes.
