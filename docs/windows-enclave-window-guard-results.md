# Windows guarded stack-window native observations

Status: synthetic public-marker experiment only, **not strict qualification**.
Windows strict constructors remain Unsupported. No production Rust, cryptography,
dependency or release-gate change results from this work.

The [design](windows-enclave-window-guard-design.md) was compiled and executed at
`b019e0887ce89dbaa2890fadae2abf758aa20679`. Unlike the earlier unguarded window,
its 64-KiB payload is page-aligned and has two separate 4-KiB boundary pages.
Setup/cleanup helpers execute below the lower boundary; the enclosing caller
frame stays above the upper one. The fixed body remains on the OS-managed stack.
No TEB edits, ordinary-memory fallback or alternate-allocation stack is involved.

## Outcomes on the development host

Windows Server 2025 build 26100.33438, native AMD x86-64, VBS/HVCI running,
Secure Boot disabled, test signing enabled. Python 3.13.15; MSVC directory
14.44.35207; SDK directory 10.0.26100.0. These are development-only observations.

| Control | Exact observed outcome |
| --- | --- |
| [Normal](../assurance/windows-protection-observations/window-guard-normal-b019e088.json), three calls | Two no-access boundary pages; sixteen payload pages locked before entry and after full zero readback; work markers 31, result 95; both boundary protections restored |
| [Caught SEH exception](../assurance/windows-protection-observations/window-guard-normal-unwind-b019e088.json), three calls | Local finally and handler execute; markers 47, result 111; locking, clearing and restoration checks pass |
| Read/write at each boundary, three calls per mode, repeated with caught-SEH mode | Two access violations per call, exact target address and read/write kind; zero successful forbidden accesses; both pages remain no-access after both attempts |
| [Denial](../assurance/windows-protection-observations/window-guard-deny-b019e088.json) and [denial with exception requested](../assurance/windows-protection-observations/window-guard-deny-unwind-b019e088.json), three calls each | No work or body addresses, no payload lock acquisition, zero readback succeeds, result 64, boundary pages restored |
| [Missing clear](../assurance/windows-protection-observations/window-guard-mutant-b019e088.json) and [missing clear with SEH](../assurance/windows-protection-observations/window-guard-mutant-unwind-b019e088.json), one call each | Work runs but zero check rejects; result zero, no finish callback, payload lock retained until teardown; access protections restored without claiming erasure |
| Normal and mutant expectations deliberately reversed | Both fail with the exact execution/cleanup outcome diagnostic |
| [Compiled missing-guard image](../assurance/windows-protection-observations/window-guard-missing-guard-b019e088.err) | Setup rejects at stage 2; no work/body/authority admission; finish is not accepted without admission; runner exits 1 with no success JSON |

The four boundary records are
[read-low](../assurance/windows-protection-observations/window-guard-read-low-b019e088.json),
[write-low](../assurance/windows-protection-observations/window-guard-write-low-b019e088.json),
[read-high](../assurance/windows-protection-observations/window-guard-read-high-b019e088.json) and
[write-high](../assurance/windows-protection-observations/window-guard-write-high-b019e088.json).
Their corresponding `-unwind` records are retained alongside them. Across those
eight modes there are 24 calls and 48 exact boundary faults. Persistent
PAGE_NOACCESS behavior is checked, not inferred from a single one-shot alarm.
These direct boundary accesses are deliberately made with exception-handler
headroom; they are not stack-exhaustion tests.

All [seventeen runner outcomes](../assurance/windows-protection-observations/window-guard-run-exits-b019e088.json)
match their expected result. Expected mutation failures are not ordinary passes.
[Ten guard regressions and fourteen handshake regressions](../assurance/windows-protection-observations/window-guard-tests-b019e088.txt)
passed natively and locally. Their mock cases test orchestration rather than
supplying extra native page-protection evidence.

## Provenance and cleanup

The [build](../assurance/windows-protection-observations/window-guard-build-b019e088.txt)
uses the enclave libraries and `/W4 /WX`, builds normal/missing-clear/missing-guard
images, and emits disassembly/unwind descriptions. The
[first-party frame excerpt](../assurance/windows-protection-observations/window-guard-frame-b019e088.txt)
retains admission before fill/body, full clear/readback, finish only after zero,
and unconditional boundary restoration before frame return. RBP unwind metadata
is present; its presence alone is not a general unwind qualification.

All eleven source hashes match the capture revision. Downloaded signed images:

- Normal SHA-256: `e0dca266b6a3a849a636f3d256347a8c69e2b92718c4729a9ec26d58d7baa6d1`.
- Missing-clear: `cd97e58539fb9b3c51125438fbfd817afeefcdb4b556c97298ece8ff469d96c6`.
- Missing-guard: `eb34024e40d7133ed725ea46f9fd321461a74a4cfa840d52f357928d8b78d5ed`.

Raw archive SHA-256, matching on host and local download:
`aa1af7e2d7de4fc18ef309da6860d1e2be658e4cad97f89dbab81d53990504cc`.
Raw disassembly SHA-256:
`20fa7a2486a020f29eac8dec1dd4e58b1622503a83030decd9b8945752fe0565`.
Only first-party disassembly excerpts are committed; binaries and full raw
artifacts remain in the local-only backup outside Cargo target directories.
Committed transcripts normalize CRLF and trailing whitespace.

Two launcher errors were corrected before the final controls: PowerShell treated
Git stderr as an error, and a ProcessStartInfo instance lacked an explicit working
directory. Neither is counted as native evidence. The key-based login's attempt
to create a user-store signing key returned Access Denied. An ephemeral
non-exportable machine-store key was used instead, without adding trust roots.
[Signing](../assurance/windows-protection-observations/window-guard-sign-b019e088.txt)
still warned with exit 2 about VBS compatibility; the wrapper failed and removed
the certificate/private key. Images were inspected and used for development-only
tests, never represented as clean production signing. The final
[cleanup](../assurance/windows-protection-observations/window-guard-cleanup-b019e088.json)
reports zero probe processes and zero temporary certificates across user and
machine stores. No crash dumps were requested or copied.

## Remaining boundary

The subsequent [fixed-frame depth experiment](windows-enclave-window-depth-results.md)
now records bounded rejection and exact-exception unwinding separately. A page access
fault near the top of the window does not prove recovery with an exhausted stack,
prevent a large frame from skipping a page, or bound the full runtime call graph.
Rust ABI/panic handling, complete secret-bearing worker/TLS/register ownership,
concurrency, exact-layout dump behavior and production signing remain unresolved.
Host cooperation is still trusted for residency. These results do not make a
malicious host/hypervisor unable to interfere and do not enable Windows strict.
