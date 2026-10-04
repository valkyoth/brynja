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

## Remaining boundary work

1. Review actual linked worker/caller flow and callbacks made while workers are
   still running. The completed **return** boundary does not prove VBS transition
   register handling or sanitize every active callback boundary.
2. Qualify final linked caller/spill/cleanup paths and current-image dump behavior.
   Nonvolatile caller state is preserved, not erased. AVX-512-only state, fatal
   aborts and interruption contexts are not covered by this wrapper probe.
3. Refresh other affected algorithm images before claiming their new-image
   qualification, reconcile compiler/platform coverage, then obtain independent
   pentest. The two rebuilt routes do not silently qualify the remaining images.

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
