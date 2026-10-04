# Windows enclave whole-image cleanup status

Whole-image cleanup qualification is **not complete**. Native functional results,
owned-memory clearing, opaque-kernel register erasure and whole-image caller/ABI
cleanup are separate claims. None of the new diagnostics changes release gates,
production code, signed images or the previous functional observations.

## Stack-wrapper register diagnostic, 2026-10-04

The sequential `PublicLockedFrame` and concurrent `PublicStackFrame` wrappers
clear and read back a 64-KiB worker stack window. They do not explicitly scrub
volatile vector registers. A native Windows process diagnostic now links the
**unmodified** wrappers to synthetic assembly bodies which fill XMM0–5, or YMM0–5
when Windows reports AVX available, with public `0x5a` and `0xa5` sentinels.
Assembly snapshots run at cleanup-callback entry and immediately after wrapper
return, before compiler-generated test code can overwrite the observations.

All six sentinels survive at both boundaries for both wrappers. The 16-case
baseline also checks denied admission, which does not execute the poisoning body
and retains the explicitly zero initial register state. Two compiled measurement
mutants remove poisoning or the finish snapshot: all sixteen admitted mutant
cases reject, while sixteen denied controls still match. Compilation errors,
unsupported instructions and crashes are not accepted as mutation detection.

The probe executes in an ordinary Windows process, with stubbed admission,
finish and restore functions. It does **not** run actual Rust cryptographic
bodies, VBS transitions, page protection or residency. The result proves that
these wrappers alone are not vector-register scrubbers; it does **not** establish
secret disclosure from an existing enclave or undo the opaque-kernel erasure
results. GPRs, nonvolatile vectors, AVX-512 state and interruption paths are not
covered by this probe.

The [observation record](../assurance/windows-protection-observations/register-boundary-20261004.json)
binds sources, compiler identity, logs, binaries and the saved signed concurrent
image. A separate bounded COFF/PE inspector finds the exact 244-byte concurrent
wrapper at RVA `0x82f0`, allowing only the five enumerated call relocations. It
requires a unique executable match, exact runtime-function extent and distinct
in-image executable call targets. Seven parser tests include malformed/truncated
input, instruction corruption, relocation substitution, ambiguous matches and
out-of-image targets. This establishes wrapper identity, **not** callee semantics,
signature validity or whole-image qualification. Sequential image binding is not
implemented by that inspector.

## Remaining boundary work

1. Review actual linked worker/caller register flow and the VBS transition
   boundary. Add and test explicit ABI-compatible cleanup where required; do not
   assume an OS transition or stack clearing proves register erasure.
2. Preserve public return values and Windows nonvolatile-register obligations;
   admit every required extended-state instruction before entering it. Test
   success, rejection and cleanup-error routes, with compiled omission controls.
3. Rebuild affected images and refresh their native checks if shared wrappers
   change. Qualify final linked caller/spill/cleanup paths and current-image dump
   behavior before independent pentest. Historical image records stay historical.

The Windows ABI distinguishes volatile XMM0–5 from nonvolatile XMM6–15, while
upper YMM halves are volatile. A blanket `vzeroall` would violate ordinary
callee obligations; unconditional AVX instructions would also be wrong for a
baseline-only image. See Microsoft's
[x64 register-preservation contract](https://learn.microsoft.com/en-us/cpp/build/x64-calling-convention?view=msvc-170).

## Reproduction

From an x64 Visual Studio developer prompt in a Windows checkout:

```sh
python scripts/cryptography/test-windows-enclave-register-boundary.py
python scripts/cryptography/windows_enclave_register_boundary.py FRESH_DIRECTORY
```

AVX availability is required for this complete diagnostic matrix. Absence fails
the run; it is not silently recorded as coverage. The runner records the present
residue behavior, not a release acceptance criterion requiring residue forever.
An intentional cleanup change must update this diagnostic's expected results.

The linked-image inspector and its synthetic tests run on Linux or Windows:

```sh
python3 scripts/cryptography/test-windows-enclave-wrapper-binding.py
python3 scripts/cryptography/windows_enclave_wrapper_binding.py CONCURRENT_FRAME_OBJ SIGNED_DLL PublicStackFrame
```

Raw artifacts are retained locally outside `target/` under
`release-reports/windows-local-20261004/register-boundary-final-20261004/`.
Development-only signing, caller copies, fatal aborts, arbitrary snapshots and
unsupported Windows ARM64 remain separate limitations, not qualified here.
