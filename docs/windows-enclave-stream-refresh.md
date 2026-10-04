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
ARM64. Other affected images still need reconciliation; the subsequent scalar
refresh and public-route inventory below make that remaining scope explicit.
Release-gate policy is unchanged.

Raw evidence is saved alongside the earlier captures, under `kmac-stream-cleanup`,
`tuple-stream-cleanup-complete`, their admitted/host directories, and
`tuple-gate-complete-linux`. `verify_kmac_tuple_cleanup.py` reproduces the new
observation and checks source, binary, image and command-log hashes. Failed
attempt logs remain in their separate directories; none contributes passing
TupleHash evidence.

## Scalar streaming follow-up and route inventory

The subsequent [scalar refresh](../assurance/windows-protection-observations/stream-scalar-refresh-20261004.json)
rebuilds the four separate scalar streaming images with the current wrapper.
Each now has positive native host execution, not merely use as a historical
rejection control. Source/generated-artifact hashes reconcile with the checkout,
import preparation reproduces byte-for-byte, and each signed image contains the
reviewed 392-byte `PublicLockedFrame`.

| Check | SHA-2 | SHA-3/SHAKE/cSHAKE | KMAC | TupleHash |
| --- | --- | --- | --- | --- |
| Component tests | 7 | 7 | 13 | 8 |
| Native host cases per debug/release profile | 631 | 1,028 | 546 | 230 |
| Lifecycle tests per profile | 22 passed, 3 ignored | 33 passed, 6 ignored | 26 passed, 4 ignored | 26 passed, 4 ignored |
| Scoped Windows Clippy | PASS | PASS | PASS | PASS |

These are fresh functional/component tests under Rust 1.98.1, not a fresh
mutation campaign or an all-toolchain sweep. Explicit ignored native campaigns
were selected individually and required to execute; other ignored lifecycle
tests are not counted as passes. Production code and release-gate policy did
not change. Signing remains development-only, with temporary signing keys removed.
Wrapper identity does not establish linked caller/callee spill semantics or
whole-image dump behavior.

The [public-opening-route snapshot](../assurance/windows-protection-observations/current-image-routes-20261004.json)
enumerates all 19 current module-root public `Session::open*` constructors,
including feature-gated routes, against the recorded refreshes:

| Public route group | Routes | Wrapper refresh and native host record |
| --- | --- | --- |
| Bounded retained SHA-256 | 1 | Not yet reconciled |
| Scalar SHA-2/SHA-3/KMAC/TupleHash streaming | 4 | Recorded above |
| SHA-NI/AVX2 streaming | 4 | Recorded above |
| Sequential SHA-2/SHA-3 batches, scalar and accelerated | 4 | Not yet reconciled |
| Independent-message SHA-256/SHA-512/Keccak SIMD | 3 | Recorded in the [SIMD refresh](../assurance/windows-protection-observations/simd-host-refresh-20261004.json) |
| Sequential ParallelHash, scalar and AVX2 | 2 | Not yet reconciled |
| Concurrent AVX2 ParallelHash | 1 | Recorded in the [wrapper cleanup campaign](../assurance/windows-protection-observations/register-cleanup-20261004.json) |

Thus 12 opening routes have recorded development refresh coverage and seven
remain to reconcile. This is a source-bound checklist, **not a new release gate**,
semantic Rust parser, inventory of every historical proof DLL or whole-image
qualification. None of the 19 routes is promoted to whole-image qualification by
this count. Earlier concurrent/accelerated records were rechecked against their
saved observations and current source hashes; their limits remain unchanged.

Raw scalar builds, component binaries, prepared/signed images and host logs are
saved outside `target/` in the same local evidence directory, under
`*-scalar-cleanup-{component,image,admitted,host}` and `scalar-stream-cleanup-logs`.
`verify_scalar_cleanup.py` reproduces the scalar observation;
`review_current_image_routes.py` reproduces the constructor snapshot and verifies
its recorded evidence references. Both helpers are retained with the raw evidence.

## Sequential batch and ParallelHash follow-up

The subsequent [SHA-2/SHA-3 batch record](../assurance/windows-protection-observations/sequential-batch-refresh-20261004.json)
and [ParallelHash record](../assurance/windows-protection-observations/sequential-parallel-refresh-20261004.json)
cover six additional rebuilt images, each containing the reviewed 392-byte
`PublicLockedFrame`. Prepared imports reproduce byte-for-byte locally; build
and host source hashes reconcile with the implementation at `3b950c64`.

| Sequential route | Native host work per debug/release profile |
| --- | --- |
| Scalar SHA-2 batch | 355 batches, 1,822 digests |
| SHA-NI SHA-2 batch | 291 batches, 1,312 digests |
| Scalar SHA-3/SHAKE/cSHAKE batch | 323 batches, 1,344 digests |
| AVX2 SHA-3/SHAKE/cSHAKE batch | 323 batches, 1,344 digests |
| Scalar ParallelHash | 332 direct and 256 retained comparisons |
| AVX2 ParallelHash | 332 direct and 256 retained comparisons |

Scalar component suites pass 10, 10 and 16 tests respectively. Accelerated
component/resident/worker suites pass 9/4/12/1 for SHA-2, 11/12/1 for SHA-3 and
11/20/1 for ParallelHash. Host lifecycle checks pass 32 tests (7 ignored) for
the shared SHA-2 feature profile and 45 (11 ignored) for the shared SHA-3 and
ParallelHash profile, in debug and release. These shared checks are not counted
again for every image. Each native campaign is selected explicitly despite its
normal ignored status. Scoped Windows Clippy passes for all three families.
ParallelHash's saved oracle is regenerated and compared locally.

One incomplete SHA-3 capture is excluded: the native scalar test passed, but
the capture helper expected `SCALAR` instead of the test's `scalar` marker.
After correcting that exact marker check, the complete SHA-3 campaign was
rerun in a fresh directory and passed. Original logs remain retained.
No production code changed, and this refresh is not a fresh mutation campaign
or all-toolchain sweep.

Accelerated negative tests deliberately corrupt export metadata. They verify
rejection without output commit and quarantine, then observe `Error::Release`:
uncertain resources remain until the isolated child process exits. That result
is **not** evidence of confirmed clean release on those injected paths.
Positive execution uses development transport; production constructors reject
the development signatures. Temporary signing keys were removed, and signing
compatibility warnings remain recorded. These sequential routes do not prove
multibuffer SIMD, concurrent scheduling or dedicated x86 SHA512 execution.

The [updated constructor snapshot](../assurance/windows-protection-observations/current-image-routes-sequential-20261004.json)
now records development refreshes for 18 of 19 public opening routes. Only the
bounded retained SHA-256 image refresh remains; the earlier 12-route snapshot
is preserved as a historical observation. Whole-image caller/spill and SDK
review, remaining-image dump coverage and independent retest are still open.
Release-gate policy and production-signing requirements are unchanged.

Raw builds, signed images, binaries and logs remain outside `target/`, beside
the earlier captures, in `sha2-seq-*`, `sha3-seq-*` and `parallel-seq-*`
directories. `verify_sequential_batch_cleanup.py` and
`verify_sequential_parallel_cleanup.py` reproduce the new records;
`review_sequential_image_routes.py` checks their constructor references.
