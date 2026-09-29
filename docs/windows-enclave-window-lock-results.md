# Windows live stack-window residency experiment

Status: synthetic public-marker mechanics only, **not strict qualification**.
Windows strict constructors still return Unsupported. No production crypto,
dependency, release-gate or Linux guarantee changed.

## Mechanism and trust

This extends the [OS-stack window experiment](windows-enclave-window-results.md)
with separate source files, preserving the earlier image/source bindings. Capture
commit: `5200086c20bbf8a6fa10253a5d3cfb62ec0c9425`.

The assembly frame reserves/probes a 64-KiB window on the OS-managed enclave
stack. Before filling it or calling its fixed C body, it calls a bootstrap helper
below the window. That helper uses [CallEnclave](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-callenclave)
to request a synchronous trusted-host callback. Only public window geometry
leaves the enclave; the host never dereferences enclave contents.

The host bounds-checks the window, rounds both edges to pages, refuses existing
locks, calls VirtualLock, and requires a valid/locked QueryWorkingSetEx result
for **every** covered page before acknowledging entry. Refusing existing locks
matters because [VirtualLock has no lock reference count](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).
This is single-worker experiment orchestration, not a general concurrent lock
ownership protocol or attestation against a malicious host.

After the fixed body returns, assembly reclaims the window through RSP, clears
every qword and reads the complete region back. Only a zero result permits the
finish callback. The host rechecks all pages are still locked, then unlocks and
acknowledges completion. Normal return and one exact SEH exception caught
**inside** the window are tested; arbitrary faults are not converted to success.

Denial skips both fill and body, but still clears/readbacks the reserved window.
A missing-clear image cannot send the finish notification. Its acquired lock is
left for teardown, not explicitly released while dirty. Teardown is not an
erasure claim. Callback exceptions are caught at the Python ABI boundary,
return denial/failure, and remain errors even if the later cleanup handshake
succeeds. No ctypes callback exception can silently become a successful record.

## Native observations

Replacement Azure development host: Windows Server 2025 build 26100.33438,
native AMD x86-64, VBS/HVCI running, Secure Boot disabled, test signing enabled.
Python 3.13.15, MSVC directory 14.44.35207, SDK directory 10.0.26100.0.

| Control | Observed outcome |
| --- | --- |
| [Normal](../assurance/windows-protection-observations/window-lock-normal-5200086c.json), three repetitions | 17 pages locked before body entry and after complete clear; markers 31; result 95; unlock follows clear |
| [Caught exception](../assurance/windows-protection-observations/window-lock-unwind-5200086c.json), three repetitions | Same 17-page checks; local finally and handler markers 47; result 111 |
| [Denial](../assurance/windows-protection-observations/window-lock-deny-5200086c.json) and [exception-request denial](../assurance/windows-protection-observations/window-lock-deny-unwind-5200086c.json), three each | No lock acquisition, no body/local-frame addresses, no work markers; complete zero readback; result 64 |
| [Missing clear](../assurance/windows-protection-observations/window-lock-mutant-5200086c.json) and [missing clear with exception](../assurance/windows-protection-observations/window-lock-mutant-unwind-5200086c.json), one each | Body runs; clear verification fails; no finish callback or explicit unlock; result zero |
| Opposite normal/mutant expectations | Both runners fail with the exact outcome-mismatch diagnostic |
| Callback faults after lock, after observation, before unlock | All runners fail with their original injected-fault diagnostic and emit no successful JSON |

The [run exits](../assurance/windows-protection-observations/window-lock-run-exits-5200086c.json)
and [runner transcript](../assurance/windows-protection-observations/window-lock-run-5200086c.txt)
preserve all eleven controls. Fault stderr records remain alongside them.
Fourteen focused tests passed locally and natively, covering page edges,
preexisting locks, denial, replays, wrong addresses/order, callback recovery,
retained locks on failure, exact schemas, timeouts, teardown and source ordering.
Those mocked tests are not additional native residency evidence.

The [emitted first-party frame](../assurance/windows-protection-observations/window-lock-frame-5200086c.txt)
retains admission-before-fill, branch-around-body on denial, full clear/readback,
finish-after-zero, and RBP unwind metadata. Complete raw disassembly remains in
the local-only backup; no vendor runtime implementation is committed.

## Provenance and limits

All ten source hashes and both signed image hashes were checked after download.
Normal image SHA-256: `235b19a434651e21881415ad786e7d01b6c7d65c10bfce76e827903dd7356cbd`.
Mutant image SHA-256: `ce5bd1c60f6c9ab2579da6f45bb8a55c56a994762f6ebe0cac99389e1b5f5d8f`.
Raw archive SHA-256: `52b03166660cfcd12558d01527d332744e63de730568d5dc06f86b4c7c1338a9`.
Stored records normalize CRLF and trailing whitespace only.

The [build](../assurance/windows-protection-observations/window-lock-build-5200086c.txt)
passes with warnings denied. An initial helper object-name collision was fixed;
that failed build is retained locally. A PowerShell launch-wrapper attempt also
failed on a missing exit value; the corrected wrapper reran every control using
an owned Process handle. Neither attempt is counted as a successful observation.
The [signing wrapper](../assurance/windows-protection-observations/window-lock-sign-5200086c.txt)
failed on SignTool's compatibility-warning exit 2. The signed images were used
only after explicit development-only inspection, not as production signing proof.
The temporary signing identity/key was deleted; [cleanup](../assurance/windows-protection-observations/window-lock-cleanup-5200086c.json)
found no retained probe process or temporary certificate. No crash dumps were
requested or copied during this experiment.

Still unproved: enforced call-depth/window guards, the complete exception/runtime
stack/TLS footprint, register cleanup, Rust ABI/panics, arbitrary closures,
concurrency, full worker lifecycle, dump exclusion for this exact layout, Windows
Arm, and production signing. Page rounding covers adjacent portions of the same
OS stack; it does not establish independent storage ownership. This callback
handshake assumes trusted host cooperation and cannot establish residency in
spite of a malicious host or hypervisor. Next: establish a bounded execution
contract and its failure behavior before attempting production integration.

The [guarded-window prototype](windows-enclave-window-guard-design.md) is the
next experiment. Its local mock regressions do not extend these native results;
native compilation and page-boundary execution are still pending.
