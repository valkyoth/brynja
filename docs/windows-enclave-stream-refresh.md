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
KMAC and TupleHash streaming images were still pending at that point; the
follow-up below completes those two refreshes, not an exhaustive image inventory.
Release-gate policy is unchanged.

Raw builds, signed images, test binaries and logs are retained outside `target/`
in `release-reports/windows-local-20261004/`, under `sha2-stream-cleanup`,
`sha3-stream-cleanup-retry`, their `*-stream-cleanup-admitted` and
`*-stream-cleanup-host` directories. `verify_stream_cleanup.py` reproduces the
committed observation from these saved artifacts and checks current source hashes.

## KMAC and TupleHash follow-up

The subsequent [KMAC/TupleHash refresh](../assurance/windows-protection-observations/stream-kmac-tuple-refresh-20261004.json)
rebuilds both separate AVX2 streaming images with the same reviewed wrapper.
Build-source/generated-artifact hashes match, import preparation reproduces
byte-for-byte, and the exact 392-byte wrapper is bound in each signed image.

| Check | AVX2 KMAC | AVX2 TupleHash |
| --- | --- | --- |
| Component tests | 16 | 9 |
| Compiled Rust worker mutants rejected | 9 | 9 |
| Compiled baseline C gate/entry mutants rejected | 18 | 18 |
| Native VBS calls / comparisons | 672 / 50 | 853 / 50 |
| Host cases per debug/release profile | 546 | 230 |
| Lifecycle tests per profile | 26 passed, 5 ignored | 26 passed, 5 ignored |
| Scoped Windows Clippy | PASS | PASS |

Three incomplete TupleHash attempts remain excluded. First, a generated C
assertion exceeded the unchanged ten-second test timeout. Correlated Windows
fault/report events span 23.2493745 seconds; no raw crash dumps were collected.
Two following attempts failed to relink a just-executed output (`LNK1104`), first
C and then Rust. The specific file-open cause is not established.

The test harness now gives each Rust/C mutant and restored Rust baseline its
own executable. Its generated **test-only** C assertion retains every condition,
prints a dedicated diagnostic and exits with code 97. Negative cases require
both that code and diagnostic; arbitrary crashes, missing assertions, timeouts
and unexpected success are rejected. Compiled positive/negative sentinels verify
that assertions still execute under `NDEBUG`. Production Rust/C/assembly and
Windows security settings are unchanged.

The complete corrected TupleHash campaign passes on Linux x86-64 and Windows
x64: nine Rust and eighteen C gate/entry mutants rejected on each. Each platform
also retains all 24 C test binaries: five successes and nineteen deliberate
assertion failures, including one assertion sentinel (not an extra gate mutant).
The original timeout is unchanged, not increased or waived.

All signing, historical-scalar-control and qualification limits above still
apply. These four accelerated streaming refreshes do not exhaust the image
inventory or qualify whole-image spills, dumps, production signing or Windows
ARM64. Other affected scalar/sequential/batch images still need reconciliation.
Release-gate policy is unchanged.

Raw evidence is saved alongside the earlier captures, under `kmac-stream-cleanup`,
`tuple-stream-cleanup-complete`, their admitted/host directories, and
`tuple-gate-complete-linux`. `verify_kmac_tuple_cleanup.py` reproduces the new
observation and checks source, binary, image and command-log hashes. Failed
attempt logs remain in their separate directories; none contributes passing
TupleHash evidence.
