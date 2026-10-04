# Windows enclave whole-image cleanup status

Whole-image cleanup qualification is **not complete**. Native functional results,
owned-memory clearing, opaque-kernel register erasure and whole-image caller/ABI
cleanup are separate claims. Shared development-image stack wrappers now have
explicit register clearing, tested in both rebuilt wrapper families. No Rust
cryptographic primitive, public host API or release-gate policy changed.

## Completed wrapper boundary, 2026-10-04

Both `PublicLockedFrame` and `PublicStackFrame` now clear XMM0–5 and, when
CPU/OS AVX state is available, the upper halves of YMM0–15. Clearing runs after
the worker returns, before stack reclamation and its cleanup callback, and again
after the restore callback just before wrapper return. The final step also clears
RCX, RDX and R8–R11; RAX retains the public scalar result. The pre-reclamation
step preserves the public worker result in R8. No secret register is spilled to
implement the clear.

The setup checks CPUID XSAVE/OSXSAVE/AVX and XCR0's XMM/YMM bits before enabling
`vzeroupper`. RBX is preserved across CPUID in R10, not a new stack spill. The
cached result is public metadata; it is not worker instruction authority or a
live CPU-migration monitor. Existing deployment-stability and accelerated-worker
admission requirements remain. XMM6–15's low halves are preserved to respect
the Windows ABI.

The updated native process probe snapshots public sentinels before clearing,
at cleanup-callback entry and after return. Restore stubs deliberately poison
the registers again, so a missing final wipe cannot hide behind the earlier
wipe. It also measures preserved RBX/XMM6–15, cleared upper YMM6–15 and the six
volatile GPRs at return. The 32-case baseline spans both wrappers, SSE2/AVX,
admitted/denied bodies, two sentinels and successful/failed restore callbacks.
Nine compiled controls/mutations yield 208 expected rejections and 80 unaffected
control cases. Missing poison/snapshot, either clearing boundary, XMM clearing,
upper-half clearing, GPR clearing and RBX preservation are exercised separately.
The forced-baseline control tests the no-AVX branch on an AVX-capable machine;
it is **not** native coverage on an AVX-unavailable machine.

Actual rebuilt, development-signed VBS images also pass:

- Concurrent ParallelHash: 31 scheduler cases; the actual crate host's 68 cases
  in each of debug/release, five compiled lifecycle controls, restored-source
  rerun and Clippy. This includes native denial and partial-dispatch paths.
- Sequential Keccak: 318 calls, 53 comparisons/212 lanes, public output and
  rejection/cleanup paths. Fresh component and worker suites each cover 520
  oracle cases and fourteen compiled mutations before the image build.

The [source-bound cleanup record](../assurance/windows-protection-observations/register-cleanup-20261004.json)
binds full local manifests, source/binary hashes and both signed images. Temporary
development signing keys were removed; the SDK compatibility warning is retained.
Prepared import transformations were independently reproduced byte-for-byte
locally. The COFF/PE inspector binds the exact tested wrappers to both images;
the sequential form also binds its two writable, non-executable stack-bound
globals and rejects inconsistent or aliased references. Nine parser tests cover
malformed inputs and binding substitutions. This is not signature verification
or proof of callee semantics.

## Active callback-frame observations, 2026-10-04

The concurrent scheduler calls the host for dispatch, close and join while the
root worker is still live. These are distinct from the final cleanup callback.
A separately instrumented development image retains the original Rust archive
and stack wrapper and measures the C callback's return-address slot, reply slot
and call-entry stack pointer before and after each active callback. It records
only public addresses and counts, never register contents or payload bytes.

All 31 native VBS scheduler cases passed, including zero-input, partial waves,
denial, partial dispatch and early-return paths. Across 270 active callbacks,
the measured frame/reply/shadow-space extents stayed inside the admitted root
window. Counts are checked against the separately recorded host event sequence;
each callback requires both before and after observations. Existing functional,
join, error, stack-clear and residency checks remain in the campaign.
Two additional compiled measurement variants omit the before-count or report
an out-of-window reply address. Both are rejected on a five-wave run while
their zero-wave controls pass. Crashes and compilation failures do not count as
measurement rejection. Seven focused Python tests cover the validator and probe.

The emitted diagnostic `notify` function has one fixed 48-byte allocation and
one saved RDI; RBX/RSI are saved in caller home space. Its RSP does not change
between the two measurements and the actual `CallEnclave` call. The four-byte
measurement helper is `mov rax,rsp; ret`. The local review verifier matches the
177-byte `notify` body to each signed image, allowing only six named REL32
references, and checks the exact runtime-function extent and measurement-helper
target. It also binds the unchanged stack wrapper. This is a review aid, not a
new release gate or a general disassembly verifier.

The [source-bound observation record](../assurance/windows-protection-observations/callback-stack-20261004.json)
binds the three images, source closures, original build manifest and native
results. Artifacts and the repeatable local verifier are saved under
`release-reports/windows-local-20261004/`, outside `target/`. Temporary development
signing keys were removed; signing compatibility warnings remain recorded.

This establishes the **measured instrumented callback-frame placement**, not
equivalence to the uninstrumented image or whole-image spill cleanup. It does
not measure live registers across the VBS transition, SDK-internal stack depth,
signal/interrupt state or dump inclusion. In particular, it is not evidence
that the OS clears every register at an active callback. Those remain separate
review and qualification tasks.

## Active callback-register observations, 2026-10-04

A separate instrumented scheduler image now places public `0x5a` or `0xa5`
patterns in all sixteen XMM/YMM registers and eleven general registers before
calling the real `CallEnclave` import. The measured GPRs are RAX, RBX, RBP, RSI,
RDI and R10–R15. RCX, RDX, R8 and R9 carry the API's public arguments; RSP remains
the stack pointer. The diagnostic saves/restores nonvolatile caller state in a
312-byte frame, checks that frame against the live admitted root window, and
erases its saved copies on normal return. AVX entry and `vzeroupper` require
CPUID XSAVE/OSXSAVE/AVX and the XCR0 XMM/YMM state bits. It is a measurement
fixture, **not** a production callback scrubber or arbitrary-unwind qualification.

A host assembly callback captures registers before entering C or Python. Only
root dispatch/close/join callbacks write the capture buffer; leaf callbacks do
not race that buffer. The results retain `zero`, `pattern` or `other` classifications,
not raw host-register values. A pattern match means at least four consecutive
sentinel bytes, including partial-register/zero-extended remnants; it does not
detect arbitrary transformations or shorter remnants. The enclave-side record
retains the last pre-call snapshot and a total execution count, while host-side
observations are recorded separately for every active callback.

On this development Windows 11 build **26300.9457**, twenty native cases cover
SSE2/AVX, two patterns, zero-input, five-wave and 33-wave operation, early host
return and worker denial. All existing scheduler functional/lifetime checks
passed. Both measurement modes run on an AVX-capable host; this is not native
qualification on AVX-unavailable hardware. Across **552 active callbacks**, none of the 14,904 measured register
classifications contained the four-byte pattern: 8,280 were zero and 6,624 were
other values. This does **not** mean every register was zeroed, nor does it prove
where the SDK/OS saved the live enclave state.

The capture apparatus has ordinary-process positive controls: calling the same
assembly host callback directly captures all 27 patterns. A compiled host
snapshot-omission control yields zero observations and is distinguished from
that positive result. Separately, eight real VBS runs with omitted enclave
poisoning or omitted pre-call snapshots are rejected as invalid measurements;
their scheduler operations still complete successfully. Across the complete
campaign, 28 positive and 28 host-omission controls ran. Seven focused regression
tests include partial patterns at every byte offset in all measured registers.

The [source-bound transition record](../assurance/windows-protection-observations/transition-registers-20261004.json)
binds sources, signed images, ordinary-process DLLs, full observations and local
disassembly. The local verifier compares exact MASM bytes with their linked
images, allowing only enumerated REL32/REL32_1 references; the framed probe must
also match its runtime-function extent. This remains an author review aid, not
a general whole-image verifier. Temporary signing keys were removed. Final
artifacts are in `release-reports/windows-local-20261004/transition-v4-*`, outside
`target/`; earlier v3 observations cover fewer GPRs and are not the final record.

Microsoft documents [calls from an enclave to an outside callback](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-callenclave).
These observations cover that SDK/OS path on the tested build, not a new universal
register-erasure guarantee. They do not cover AVX-512-only state, flags,
interruption/fatal paths, SDK-internal spills, dumps, or equivalence of the
instrumented image to every production image. No production cryptographic code,
public API or release gate changed.

## Current scheduler dump observations, 2026-10-04

The **uninstrumented** concurrent scheduler image from the wrapper-cleanup pass
has now been exercised under a narrowly scoped full-WER-dump experiment. The
image was not rebuilt or modified for the experiment. Only the diagnostic host
adds deliberate fail-fast checkpoints; all inputs are deterministic public
fixtures. Each child uses a unique executable name and a temporary application
LocalDumps subkey, without changing the global dump policy.

Two repetitions cover each of three checkpoints:

- Root admitted and locked, before its first dispatch: one live 64-KiB window.
- Second-wave admission barrier, after the first four leaves completed: the
  root and four workers have five disjoint locked windows. The workers are held
  **before** their current bodies, not sampled during compression.
- Successful public output, before enclave teardown: the independent oracle,
  scoped joins and all eighteen frame cleanup/unlock records have passed.

Each dump must contain an ordinary 8,192-byte positive control and the exact
33-byte public output staging region: untouched `0xa5` before export, or the
independent expected result after export. Missing, corrupt or partial controls,
the wrong crash code and missing dumps all reject. Zero-filled included enclave
bytes are counted as inclusion, never mistaken for absence.

In the six observed dumps on Windows build 26300.9457, those ordinary controls
were present, while no bytes from the measured windows or the entire 256-MiB
enclave reservation were included. Live checkpoints also checked all sixteen
pages per window were locked. The normal 31-case scheduler suite passed after
the first campaign. Nine focused regressions cover parsing, phase/population,
source binding, false-exclusion controls, timeout and temporary-file/policy
cleanup. The independent oracle files are explicitly bound because their dynamic
loader does not register them in Python's module table.

The [source-bound observation record](../assurance/windows-protection-observations/scheduler-dump-20261004.json)
binds the existing signed image/build chain, diagnostic sources and redacted
results. Raw dumps were analyzed **inside the guest and deleted**, never copied
to the repository. The unique executable, child, temporary dump folder and
application policy were confirmed absent afterward. The saved local verifier
checks source/image bindings and redacted results; it cannot reparse deleted
raw dumps. This is development-overlay evidence, not a clean-commit or
production-signing claim.

This qualifies only the observed WER path and this scheduler image. It does not
establish absence of secret-derived copies elsewhere in the process, inspect
thread-context register records, prove SDK/caller spill cleanup, test arbitrary
mid-compression interruptions, or establish destructor execution after fail-fast.
Other algorithm images still require their own applicable qualification.

## Selected linked caller review, 2026-10-04

A bounded COFF/PE review helper now examines the **same uninstrumented scheduler
image** used for the dump observations. It binds 56 of 66 selected function
entries to saved compiler objects, matching every non-relocated instruction byte,
resolving all enumerated REL32 references and requiring exact runtime-function
extents. The selection comprises the primary Rust object's 57 emitted unwind
entries and nine C adapter functions, not every function in the image. Eleven
synthetic regression tests pass on Linux and Windows; malformed identities,
relocations, permissions, extents and unwind chains reject. The image was neither
rebuilt nor rerun for this inspection.

The actual uninstrumented `PrivateWaveDispatch` inlines its three active
`CallEnclave` callbacks. Its 735-byte body has four contiguous chained unwind
regions, including delayed nonvolatile-register saves; the primary fixed
allocation plus pushes is 72 bytes. This differs from the separate 177-byte
instrumented callback used in the earlier frame-placement campaign. Neither
campaign is silently treated as proof of the other's emitted code.

The selected Rust root has 11,160 bytes of fixed allocation plus pushes and
additional alignment adjustment; the leaf has 136 bytes. The root closure's
references are bound to the actual C dispatcher, and the root's input/output
references are bound to the actual copy adapters. The copy adapters reach
six-byte indirect jump thunks for `EnclaveCopyIntoEnclave` and
`EnclaveCopyOutOfEnclave`; the import table also identifies `CallEnclave` in
`vertdll.dll`. These are **local frame and import identities**, not maximum
transitive stack depth, runtime placement or SDK-implementation spill proofs.
Caller home-space saves and nonvolatile vector saves outside opaque kernel
blocks still require caller-level reasoning. Opaque-block no-spill evidence
does not erase those ABI obligations.

That initial inspection left ten selected entries unresolved: two panic helpers lacked a
unique byte match; three Rust functions share sections with four exception
funclets; and `PublicStackBody` uses security-cookie handler metadata outside
this decoder's supported subset. Missing matches are not declared dead code,
and unsupported unwind layouts were not counted as passes or vulnerabilities.
Dependency objects retain exception funclets despite the top-level archive's
abort setting; that setting alone is not evidence that all handler paths are
absent. The review uses Microsoft's
[x64 unwind format](https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64)
for version-one records and in-function chains, not as an assertion that fatal
aborts run destructors.

The [partial-review record](../assurance/windows-protection-observations/caller-binding-20261004.json)
binds the signed image, extracted archive member, build manifest, full caller
records, disassembly, import listing and review sources. The local repeatable
verifier is `release-reports/windows-local-20261004/review_linked_callers.py`;
it also verifies the earlier saved build/signing/wrapper chain. The artifacts
are outside `target/`. This is author inspection, not independent review,
production signing, whole-image cleanup qualification or a new release gate.

### Follow-up: handler and funclet identities

The ten identity gaps above are now accounted for against the same signed image.
A separate helper reads the **actual object's** `.pdata` relocation records to
derive exact function ranges, including interior destructor funclets. It does
not infer a function's end from the next symbol or include alignment padding.
The saved assembly listing calls one destructor `dtor$54`, while the linked
object names it `dtor$55`; the object record is authoritative. The reconciled
selection remains 57 Rust runtime entries plus nine C entries, not an inventory
of every linked or external function.

For the three Rust parents, four destructor funclets and `PublicStackBody`, the
review binds the actual function bytes and the complete associated `.xdata`
section, allowing only enumerated image-relative relocations. The parents'
handler references agree on `__CxxFrameHandler3`; all four destructor targets
match their bound code ranges. The C body's handler reference identifies
`__GSHandlerCheck`. This binds compiler metadata and reference targets; it does
**not** interpret the language-specific tables as proof that an exception can
unwind safely, run all clearing operations or preserve protected residency.

The two panic helpers have identical non-relocated code shapes but different
targets. Already-verified caller references disambiguate them. Their call chain
reaches the bound Rust panic handler, then the exact C `PrivateWaveAbort` body:
`mov ecx,7; int 0x29; ret`. Microsoft's
[fast-fail contract](https://learn.microsoft.com/en-us/cpp/intrinsics/fastfail)
does not return or invoke exception handlers. The trailing emitted `ret` is not
a recovery path; retained destructor metadata is not panic-cleanup evidence.
This is static inspection of the existing image, not a new fatal-path experiment.

Eleven new synthetic tests pass on Linux and Windows, covering interior ranges,
padding/alias rejection, malformed runtime relocations, metadata mutations,
handler targets, ambiguous code and conflicting incoming references. All 49
existing focused caller/wrapper/register/callback/transition/dump tests still
pass. The earlier verifier is rerun to regenerate the incoming reference anchors;
an arbitrary user-supplied RVA is not accepted as an observation by that workflow.
The helpers themselves are review tools, not hardened untrusted-evidence loaders.

The [follow-up record](../assurance/windows-protection-observations/caller-handlers-20261004.json)
binds all ten additional records and the object/listing identity reconciliation.
Run the saved `release-reports/windows-local-20261004/review_linked_handlers.py`
to reproduce this inspection. All 66 selected caller identities are accounted
for, but actual caller/SDK spill semantics, total stack depth and whole-image
cleanup remain unfinished. No image, cryptographic implementation, public API
or release gate changed.

## Historical diagnosis before the change

The sequential `PublicLockedFrame` and concurrent `PublicStackFrame` wrappers
cleared and read back a 64-KiB worker stack window but did not explicitly scrub
volatile vector registers at `e554fc75`. A native Windows process diagnostic linked
those **unmodified** wrappers to synthetic assembly bodies which filled XMM0–5, or YMM0–5
when Windows reports AVX available, with public `0x5a` and `0xa5` sentinels.
Assembly snapshots run at cleanup-callback entry and immediately after wrapper
return, before compiler-generated test code can overwrite the observations.

All six sentinels survived at both boundaries for both wrappers. The 16-case
baseline also checks denied admission, which does not execute the poisoning body
and retains the explicitly zero initial register state. Two compiled measurement
mutants remove poisoning or the finish snapshot: all sixteen admitted mutant
cases rejected, while sixteen denied controls still matched. Compilation errors,
unsupported instructions and crashes are not accepted as mutation detection.

The probe executes in an ordinary Windows process, with stubbed admission,
finish and restore functions. It does **not** run actual Rust cryptographic
bodies, VBS transitions, page protection or residency. The result proves that
those wrappers alone were not vector-register scrubbers; it does **not** establish
secret disclosure from an existing enclave or undo the opaque-kernel erasure
results. GPRs, nonvolatile vectors, AVX-512 state and interruption paths are not
covered by that initial probe.

The [observation record](../assurance/windows-protection-observations/register-boundary-20261004.json)
binds sources, compiler identity, logs, binaries and the saved signed concurrent
image. The original bounded COFF/PE inspector found the exact 244-byte concurrent
wrapper at RVA `0x82f0`, allowing only the five enumerated call relocations. It
requires a unique executable match, exact runtime-function extent and distinct
in-image executable call targets. Seven parser tests include malformed/truncated
input, instruction corruption, relocation substitution, ambiguous matches and
out-of-image targets. This establishes wrapper identity, **not** callee semantics,
signature validity or whole-image qualification. That record is historical;
it must not be presented as a check of the changed wrappers or new images.

## Selected caller spill review (2026-10-04)

The [selected caller observation](../assurance/windows-protection-observations/scheduler-spills-20261004.json)
binds seven caller bodies to the unchanged signed scheduler image, their actual
COFF objects and generated input-bridge sources. It records a manual
instruction/source review plus a tested arithmetic model, not a new native run
or an automatic whole-program taint analysis.

For a page-aligned 64-KiB window with exclusive upper address `H`, the selected
call chains have these stack-pointer offsets after their emitted prologues:

| Caller | Entry RSP | RSP after prologue |
| --- | --- | --- |
| PublicStackBody | H - 40 | H - 208 |
| PrivateWaveRoot | H - 216 | H - 11392 |
| PrivateWaveLeaf | H - 216 | H - 352 |
| Root closure | H - 11400 | H - 11568 |
| PrivateWaveDispatch | H - 11576 | H - 11648 |
| Input/output copy adapter | H - 11400 | H - 11440 |

Root and leaf use separate per-thread windows; their depths are not added.
The root calculation includes its emitted 32-byte alignment adjustment.
Fifteen selected spans cover saved registers, the body cookie/inventory/marker
and callback replies. The dispatcher's first two replies occupy caller-provided
home space; the third occupies a local slot. All listed spans are inside the
admitted window. Saved nonvolatile registers are conservatively treated as
potential caller data, not assumed public because they appear in an ABI prologue.
Microsoft's [x64 calling convention](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention)
defines the caller home space and register-preservation obligations.

The C copy adapters manipulate pointers, lengths and status rather than directly
loading payload bytes. Actual payload copying crosses
[EnclaveCopyIntoEnclave](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclavecopyintoenclave)
or [EnclaveCopyOutOfEnclave](https://learn.microsoft.com/en-us/windows/win32/api/winenclaveapi/nf-winenclaveapi-enclavecopyoutofenclave).
Those API contracts do not establish their implementations' spill erasure.
The model therefore records only the SDK entry return-address/home-space span:
callee frame size and spill qualification remain explicitly unknown. It does
not establish maximum transitive stack depth or transactional host copying on
an SDK output-copy failure.

On supported normal returns, including ordinary rejection, the reviewed wrapper
reclaims and clears the whole window and checks it before the finish callback.
This connects the selected locations to the earlier clear/readback campaign;
it does not turn fatal exits, arbitrary unwinding or SDK internals into qualified
paths. Six geometry regressions pass on Linux and Windows, covering exact
offsets, translated addresses, complete spans, home-space bounds and alignment
underflow. These are model tests, not runtime stack-placement measurements.

## No-unwind helpers in the primary Rust object

The [additional helper record](../assurance/windows-protection-observations/caller-leaves-20261004.json)
closes an inventory gap: seven functions in the primary Rust object have no
runtime unwind entries. The earlier 57-entry Rust unwind inventory did not
include them. All **64 primary-object functions** are now byte-bound to the
saved image; combined with the selected nine C functions, this is 73 entries.
It is not the complete population of the linked image or its libraries.

| Helper | Reviewed emitted behavior |
| --- | --- |
| `zeroize_region_volatile` | Writes zero bytes without loading the previous contents; remainder and eight-byte-unrolled loops; no stack stores |
| `copy_bytes` | Bounded word/byte copy; clears RAX/RCX/RDX on return; no stack stores |
| `xor_bits` | Loads its fifth mask argument from caller stack; clears payload working RAX and shift-count RCX; no stack stores |
| `mask_byte` | This image's specialization sets no additional bits; clears working EAX; no stack stores |
| `mask_is_zero` | Clears working R10D, retaining the intended boolean result in EAX; no stack stores |
| `apply_secret_byte_mask` | Five-byte tail jump to the bound mask implementation |
| `check_authority` | Reads authority metadata and returns its status; no stack stores |

Absence of unwind metadata alone proves none of those semantic claims. They
come from manual review of the emitted instructions, pinned by object-body
hashes and exact linked bytes. Independently reproduced incoming references
identify the selected functions, including the mask tail target. Seven synthetic
tests pass on Linux and Windows, rejecting mismatched bytes, wrong-image or
conflicting anchors, unwind overlaps, writable/unmapped code and unsupported
relocation shapes. No production code, signed image or release gate changed.
This does not establish all caller data-flow, maximum stack depth, arbitrary
exception cleanup or the behavior of other archive/runtime functions.

## Remaining boundary work

The subsequent [SHA-2 SIMD refresh](../assurance/windows-protection-observations/sha2-wrapper-refresh-20261004.json)
rebuilt both SHA-224/256 and SHA-512-family AVX2 worker images with the current
wrapper. Each passed fresh component/worker tests: 402 and 602 independent
oracle cases respectively, twelve component mutations, fourteen worker mutations
and six ownership negatives per family. Four combined cleanup-mutant runs had
an assertion-failure marker but no final suite summary; the **same four saved
binaries** were additionally run with the failing oracle test isolated. All four
completed with Rust test exit 101 and an explicit one-test assertion-failure
summary. The original partial output and the isolated replay are both retained;
an unexplained crash is not substituted for that completed rejection.

Development-signed native VBS runs then passed 302 calls/53 comparisons/424 lanes
for SHA-224/256 and 318 calls/61 comparisons/244 lanes for SHA-512-family.
Both images bind the exact already mutation-tested 392-byte `PublicLockedFrame`.
Prepared import transformations reproduced byte-for-byte locally; build, native
source and artifact hashes reconcile. Temporary signing keys were removed and
compatibility warnings retained. This refresh uses Rust 1.98.1 and AVX2, not
dedicated x86 SHA512 instructions. The subsequent
[host refresh](../assurance/windows-protection-observations/simd-host-refresh-20261004.json)
passes debug/release against both SHA-2 images and the refreshed Keccak image:
403/559/521 batches and 3224/2236/2084 lane digests respectively per profile.
SHA-2 runs 32 lifecycle tests per profile; Keccak runs 45. Seven/eleven ignored
cases are not counted as execution. Scoped Clippy passes; all saved log, binary,
image and source hashes reconcile, and the 520-case Keccak oracle reproduces.
Positive execution uses internal development transport, not production signing.
This adds no remaining-image dump coverage or whole-image qualification.

The subsequent [selected SDK-frame inspection](windows-enclave-sdk-frames.md)
maps the saved System32 library's `RtlCallEnclave` register saves and copy-entry
frames into this scheduler window. It narrows the earlier SDK unknowns for one
file only; loaded-module identity, kernel storage and full callee depth remain
unqualified.

1. Complete actual linked worker/caller and SDK-boundary review. The instrumented
   callback-frame and register campaigns above are complete for their stated
   scope, not a universal transition guarantee or uninstrumented-image proof.
   The 73 selected uninstrumented caller/helper identities are now accounted for;
   seven caller bodies have the scoped spill review above. Complete the remaining
   semantic spill/handler review and linked/SDK paths.
2. Qualify final linked caller/spill/cleanup paths and remaining-image dump behavior.
   The concurrent scheduler's current-image WER observations above are complete
   only for their stated scope. Nonvolatile caller state is preserved, not erased.
   AVX-512-only state, fatal aborts and interruption contexts are not covered by
   the wrapper probe.
3. Refresh other affected algorithm images before claiming their new-image
   qualification, reconcile compiler/platform coverage, then obtain independent
   pentest. The two rebuilt routes do not silently qualify the remaining images.
   Specifically, the saved October 2 SHA-256 and SHA-512 SIMD image-build
   manifests both mismatch the current `window_rust_x64.asm` hash; their other
   eight directly recorded build-source hashes still match. Their rebuild and
   private native retest are now completed above. The October 4 Keccak SIMD image-build
   manifest matches all nine directly recorded build sources. This comparison
   is limited to those manifests, not an exhaustive algorithm-image inventory.
   A [four-stream inventory](../assurance/windows-protection-observations/stream-refresh-inventory-20261004.json)
   also identifies old wrappers in saved SHA-NI SHA-2, AVX2 SHA-3, KMAC and
   TupleHash streaming manifests. SHA-2 additionally differs in its C entry and
   worker-test script; the other three differ only in the recorded wrapper.
   The subsequent [streaming refresh](windows-enclave-stream-refresh.md) completes
   rebuilds and native worker/debug-release host tests for SHA-2, SHA-3, KMAC and
   TupleHash, binding all four to the reviewed wrapper. Other unreconciled images
   remain; the historical inventory is not relabeled as current evidence. Three
   failed TupleHash test attempts are excluded; the corrected test-only harness
   preserves assertion checks and passes completely on Linux and Windows. The
   later scalar streaming refresh adds four rebuilt images with positive
   debug/release native host campaigns. Six subsequent sequential batch and
   ParallelHash images also pass debug/release host campaigns with exact wrapper
   binding. The [updated public-route inventory](../assurance/windows-protection-observations/current-image-routes-sequential-20261004.json)
   records 18 of 19 opening routes refreshed; bounded SHA-256 remains. This
   checklist does not qualify whole-image cleanup or add a release gate.

The Windows ABI distinguishes volatile XMM0–5 from nonvolatile XMM6–15, while
upper YMM halves are volatile. A blanket `vzeroall` would violate ordinary
callee obligations; unconditional AVX instructions would also be wrong for a
baseline-only image. See Microsoft's
[x64 register-preservation contract](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170).
The AVX state prerequisite follows Intel's
[AVX detection procedure](https://cdrdv2-public.intel.com/821612/248966-Optimization-Reference-Manual-V1-050.pdf).

## Reproduction

From an x64 Visual Studio developer prompt in a Windows checkout:

```sh
python scripts/cryptography/test-windows-enclave-register-boundary.py
python scripts/cryptography/windows_enclave_register_boundary.py FRESH_DIRECTORY
```

AVX availability is required for this complete diagnostic matrix. Absence fails
the run; it is not silently recorded as coverage. The current runner requires
erasure and ABI preservation. Use the historical commit to reproduce the original
residue observation; do not apply the old expected results to this implementation.

The linked-image inspector and its synthetic tests run on Linux or Windows:

```sh
python3 scripts/cryptography/test-windows-enclave-wrapper-binding.py
python3 scripts/cryptography/windows_enclave_wrapper_binding.py CONCURRENT_FRAME_OBJ SIGNED_DLL PublicStackFrame
python3 scripts/cryptography/windows_enclave_wrapper_binding.py SEQUENTIAL_WINDOW_OBJ SIGNED_DLL PublicLockedFrame
```

Raw artifacts are retained locally outside `target/` under
`release-reports/windows-local-20261004/register-cleanup-nospill/` and the
`scheduler-register-nospill`, `scheduler-nospill-admitted`,
`shipping-parallel-nospill`, `keccak-register-cleanup`, `keccak-cleanup-admitted`
directories beside it. The older `register-boundary-final-20261004` directory
retains the pre-fix observations.
Development-only signing, caller copies, fatal aborts, arbitrary snapshots and
unsupported Windows ARM64 remain separate limitations, not qualified here.
