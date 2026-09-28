# Windows strict protected profiles

Status: design and platform-contract review in progress for v0.24.50.
Windows strict constructors remain unsupported. This document does not admit a
backend, qualify an OS, or change release-gate policy. Existing Linux behavior
and default-off acceleration remain unchanged.

## Platform review

The first implementation must preserve the
[strict protected-resource contract](strict-hardening-profile.md), not just make
the facade compile. The following primary authorities were reviewed on
2026-09-28. API availability is not platform qualification.

| Required property | Candidate Windows mechanism | Outstanding proof |
| --- | --- | --- |
| Guarded owned storage | Reserved address range with committed payload and inaccessible boundary pages | Checked page/allocation-granularity rounding; complete rollback; no accessible gaps |
| Residency | `VirtualLock` on every committed payload page | Resource-limit rejection and native residency checks; protect before admitting secrets |
| Dump exclusion | `WerRegisterExcludedMemoryBlock` | WER reporting is not a documented guarantee for every local or custom dump path |
| Protected worker stack | Separately reviewed stack lifecycle | Protect before secret execution and erase after leaving the secret stack, before release |
| Kernel boundary | Existing kernels under Windows ABIs | Preserved registers, unwind metadata, stack discipline and emitted cleanup on both architectures |

Microsoft documents that locked pages stay resident and are not written to the
pagefile until unlocked or process termination. Pages must already be committed;
inaccessible guard pages cannot be locked. Locking has a limited working-set
budget. Brynja must return a resource/protection error rather than silently
enlarging process working-set limits or continuing unlocked.
[VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).

WER exclusion accepts a 32-bit byte count and can fail because of registration
limits or process state. All conversions and acquisition results need checks.
Its documented availability starts at Windows 10 version 1703 / Windows Server
2016; that is only an API floor, not our eventual supported baseline.
[WER exclusion](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-werregisterexcludedmemoryblock).

Local dump collection is independently configured and can operate with WER
disabled; a local dump can differ from the submitted report. Therefore, we cannot
infer strict dump exclusion from successful WER registration. Test the relevant
crash paths with synthetic markers before selecting a production adapter. If the
existing guarantee cannot be met, retain `Unsupported` and obtain an explicit
owner decision; do not relabel a narrower guarantee as equivalent.
[Local dumps](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps).

Windows separates stack reservation from initial commitment, allows growth, and
frees a thread stack at thread exit. Consequently, joining and then wiping an
OS-owned stack is not a valid design. A larger ordinary Rust thread stack is not
a protected stack either. A viable adapter must establish protected execution,
leave that stack safely, and clear its complete owned region before release,
including error and recoverable-unwind paths. An ad hoc stack-pointer switch is
not an approved substitute for reviewing ABI, exception and OS stack metadata.
[Thread stacks](https://learn.microsoft.com/en-us/windows/win32/procthread/thread-stack-size).

## Implementation sequence

1. Build isolated native probes using synthetic, non-secret data for allocation,
   locking, dump handling and stack lifecycle. Record OS build, compiler, target,
   returned errors and exact exercised behavior. Do not activate strict APIs.
2. Set the supported OS/compiler baseline and resolve the stack/dump proof
   obligations. Review x86-64 and AArch64 separately.
3. Implement bounded acquisition and rollback behind the existing platform
   interface. Acquire all protections before exposing storage to secret-bearing
   code. Clear the full committed payload, including padding, while protected;
   retain safe ownership if a release step fails. Prevent stale exclusion
   registrations from surviving address reuse.
4. Integrate strict sessions and bounded worker groups. Preserve deterministic
   joins, cleanup of partially started groups, transactional outputs and explicit
   portable/accelerated selection. No weaker-memory fallback is permitted.
5. Test acquisition failures, guard violations in subprocesses, work limits,
   cancellation, unwind and complete clearing. Inspect optimized Windows code
   and run packaged API/ownership negatives, algorithm differentials and Linux
   regressions before exceptional pentest and final native collection.

No implicit changes to machine-wide dump configuration, process security policy,
or working-set limits are authorized by this design. Probe configurations must
be explicit and confined to disposable test applications/hosts.

## Native hosts and claim limits

### Initial mapping probe

The isolated Python probe calls the Windows APIs directly with synthetic bytes;
it has no dependency on Brynja's production memory or cryptographic code. On a
disposable native 64-bit Windows host with Python 3.13 or newer and Git:

```powershell
python scripts/cryptography/test-windows-protection-probe.py
if ($LASTEXITCODE -ne 0) { throw "Probe regression tests failed" }
python scripts/cryptography/windows_protection_probe.py
if ($LASTEXITCODE -ne 0) { throw "Windows API probe failed" }
```

The JSON records the commit, dirty-checkout flag, probe source hashes, Python/OS
identity, geometry and page counts. Success means **observations only**, not
strict qualification. It allocates a bounded reservation, commits two payload
pages, observes reserved guards, locks the payload, verifies each page's valid
and locked bits before/after synthetic writes, registers/unregisters WER
exclusion, reads back complete clearing, and releases the original reservation.
Failed protection or cleanup produces a nonzero exit, not a qualified record.
No working-set limits, registry settings or machine security policy are changed.
It neither collects a crash dump nor executes a protected worker: both remain
separate outstanding experiments. The guard observation is a `VirtualQuery`
state check, not a subprocess fault test. Python clearing/readback is not a
compiler-resistant Rust cleanup claim.

ABI layouts and working-set flags follow Microsoft's
[memory-region structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-memory_basic_information),
[system geometry](https://learn.microsoft.com/en-us/windows/win32/api/sysinfoapi/ns-sysinfoapi-system_info),
[extended working-set query](https://learn.microsoft.com/en-us/windows/win32/api/psapi/nf-psapi-queryworkingsetex)
and [page flags](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-psapi_working_set_ex_block).
The `Valid` bit must be set before interpreting `Locked`; a resident page alone
does not prove it is locked. Release uses the original reservation address,
zero size and `MEM_RELEASE`, as specified by
[VirtualFree](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualfree).

### Crash-dump experiment (explicit approval required)

`scripts/cryptography/windows_wer_probe.py --allow-app-local-dump` is a separate
opt-in experiment for a disposable Windows host. It copies the installed Python
executable to a unique probe name, creates only that application's `LocalDumps`
subkey, and deliberately terminates its own synthetic child with
[RaiseFailFastException](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-raisefailfastexception).
The child has two locked synthetic mappings: one registered for WER exclusion
and an unregistered positive control. The parent requires a real full-memory
dump and complete control bytes, then measures inclusion of the registered
mapping at its exact virtual address. Missing dumps, truncated data and absent
controls are errors, never evidence of exclusion. Partial inclusion is reported
as inclusion. No broad substring search is used.

Raw dumps are not printed, committed or downloaded. The test removes its own
dump directory, application-specific policy and copied executable after the
experiment; cleanup failures prevent a successful result. Existing application
keys are rejected, and global WER settings are not modified. Only selected OS
environment variables reach the child, not inherited developer/cloud tokens.
The explicit flag is required before any native setup. Do not run this test on
a production host or feed it real secrets. Native execution awaits owner
approval; portable parser and rollback tests do not prove Windows exclusion.

The bounded reader follows the
[minidump header](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_header)
and [full-memory descriptor list](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory64_list).
It rejects duplicate/overlapping descriptors, out-of-file ranges and incorrect
format/stream types before examining the two synthetic targets. This experiment
tests local crash dumps, not custom dump writers or privileged snapshots.

### Worker-stack design review

An OS fiber is a candidate for leaving a worker stack before cleanup, not yet
an approved adapter. Microsoft's
[SwitchToFiber contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-switchtofiber)
saves/restores fiber state; its
[DeleteFiber contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-deletefiber)
also names saved registers and fiber data in addition to the stack. Neither is
a promise of protected allocation or compiler-resistant erasure. A candidate
must account for saved state outside the stack, FLS/TLS destructors, stack-growth
pages and recoverable unwinding before it can satisfy the existing contract.
No Python fiber switching or unreviewed stack-pointer manipulation is being
used to imply Rust worker qualification.

### Available host

Initial observation on 2026-09-28: the mapping probe and all 15 regression tests
passed on native x86-64 Windows Server 2025 (build 26100), using Python 3.13.15
and the clean `4ea5abcd239a2a44c0f7bc8dd4305e2b034c658c` checkout. The
[committed observation](../assurance/windows-protection-observations/mapping-x86_64-4ea5abcd.json)
records 4 KiB pages, 64 KiB reservation granularity, two locked payload pages,
successful WER registration, clearing readback and release. Source hashes were
checked against the local committed probe before recording this result.
Only line endings were normalized when importing the JSON; the downloaded raw
file SHA-256 was `e5706631a1a42085c195060dd6d469b2ab2cfe5ba0e331823a935e73d0662091`.
This is one platform experiment, not Windows strict-profile qualification.
Dump exclusion, protected worker stacks and native Arm64 remain outstanding.

The first useful host is native Windows x86-64 with Administrator SSH access,
a current supported Windows SDK and the selected Rust MSVC toolchain. Request
it once runnable probes are prepared, so it need not sit idle during design.
The initial Python mapping probe is now ready for that host; SDK/Rust installation
is needed for subsequent compiled stack/ABI experiments, not this first probe.
Native Windows AArch64 must be qualified separately before claiming that lane;
Linux Arm, cross-compilation and emulation are not substitutes.

Caller-owned inputs, application-created copies, privileged snapshots,
hibernation and fatal abort remain documented limits. Passing a probe or a
functional test is not independent cryptographic review or certification.
