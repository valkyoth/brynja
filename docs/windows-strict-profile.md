# Windows strict protected profiles

Status: design and platform-contract review in progress for v0.24.50.
Windows strict constructors remain unsupported. This document does not admit a
backend, qualify an OS, or change release-gate policy. Existing Linux behavior
and default-off acceleration remain unchanged.

The [enclave feasibility review](windows-enclave-design.md) records the next
candidate architecture, its API incompatibilities and the current host blocker.
It is not authorization to substitute a weaker storage guarantee.

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
a production host or feed it real secrets. The owner approved this scoped
experiment on 2026-09-28; portable parser and rollback tests alone do not prove
Windows exclusion.

The bounded reader follows the
[minidump header](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_header)
and [full-memory descriptor list](https://learn.microsoft.com/en-us/windows/win32/api/minidumpapiset/ns-minidumpapiset-minidump_memory64_list).
It rejects duplicate/overlapping descriptors, out-of-file ranges and incorrect
format/stream types before examining the two synthetic targets. This experiment
tests local crash dumps, not custom dump writers or privileged snapshots.

#### Native result: WER registration does not exclude this local dump

Two runs on native x86-64 Windows Server 2025 build 26100, from clean commit
`5a49e0e3e2e15d4492b641af0c685468d5052233`, included **all 8,192 bytes** of
the locked, WER-registered mapping in the full local crash dump. Its synthetic
marker matched completely, as did the separate unregistered control. The
[observation record](../assurance/windows-protection-observations/wer-local-dump-x86_64-5a49e0e3.json)
therefore reports `registered_region_absent_in_this_dump: false` and
`strict_qualified: false`. All 29 mapping/parser/orchestration tests passed on
the same host. Test success does not turn the negative OS result into admission.

The first PowerShell wrapper did not retain its process exit-code property;
the Python experiment nevertheless produced its completed result. Repeating
with `Start-Process -Wait -PassThru` returned exit zero and reproduced the same
summary. Both downloaded summary files have SHA-256
`a13c40df445e95d9b0b72e93851b0024563c7e7c53a457da2cb69d892e2e60aa`;
only line endings were normalized in the committed copy. Probe-source hashes
were checked locally. Raw dumps were deleted on the host, not downloaded.
An independent remote inspection confirmed that the unique application keys,
copied executables and temporary dump directories were absent after each run.

This rejects the proposed combination of `VirtualLock` plus WER registration
as sufficient evidence for local crash-dump exclusion. It does not demonstrate
that every possible Windows design is impossible, nor does it claim a defect
in shipped Brynja code: Windows strict constructors still return unsupported.
It is consistent with Microsoft's separate
[LocalDumps configuration contract](https://learn.microsoft.com/en-us/windows/win32/wer/collecting-user-mode-dumps).

Do not silently replace region protection with a requirement to disable dumps.
Such a deployment-dependent contract would need an explicit owner decision and
separate API/documentation review. Further design work must either demonstrate
an adequate alternative or leave Windows strict support unavailable.

The reviewed alternatives are not established substitutes:

- [WerSetFlags](https://learn.microsoft.com/en-us/windows/win32/api/werapi/nf-werapi-wersetflags)
  changes process-wide WER reporting, including optional heap omission; its
  documentation does not establish exclusion of these independently configured
  local dumps. No such process-wide flag was changed in this experiment.
- [AWE](https://learn.microsoft.com/en-us/windows/win32/memory/address-windowing-extensions)
  provides nonpaged physical storage but requires the Lock Pages in Memory
  privilege and disallows ordinary page protection changes within AWE ranges.
  Those documented properties do not establish dump exclusion or a guarded
  worker-stack design. No privilege was granted or enabled for this experiment.

### AWE experiment and counterexample

The next synthetic experiment uses `windows_awe_probe.py` through
`windows_wer_probe.py --allow-app-local-dump --mapping-kind awe`. It does not
register the AWE range with WER or substitute an ordinary allocation on failure.
It maps only the middle payload pages, rejects partial physical allocation,
and clears/readbacks the complete payload before unmapping, freeing physical
pages and releasing the virtual reservation on normal cleanup. A cleanup
preflight runs before the separate deliberate crash. The dump still must contain
the ordinary-memory positive control. Unmapped boundary protection, dump
exclusion and worker-stack suitability are not assumed from this design.

This diagnostic requires an already-assigned `SeLockMemoryPrivilege`; it never
grants account rights. It enables the right only in its short-lived process and
rejects `ERROR_NOT_ALL_ASSIGNED` even if `AdjustTokenPrivileges` returns true.
The owner approved a temporary account-right grant on the disposable Windows
host for this experiment, with restoration afterward. This is not a deployment
requirement adopted by Brynja and not admission of Windows strict support.

Local tests cover allocation bounds, partial allocation/free, opaque PFN
preservation, acquisition/cleanup failures, privilege failure and mapping-kind
selection. Native results must be recorded separately; these tests are not
evidence that Windows excludes AWE memory from crash dumps.

On 2026-09-28, two native runs at clean commit
`c8f144d337d2b512a3964302acbf63b3a134bc07` on the same Windows Server 2025
build 26100 host found all 8,192 bytes of the AWE payload in the full local
crash dump, alongside all 8,192 control bytes. The
[recorded observation](../assurance/windows-protection-observations/awe-local-dump-x86_64-c8f144d3.json)
therefore rejects AWE alone as the missing dump-exclusion mechanism. Normal
mapping cleanup passed before each crash. All 39 probe regression tests passed
locally and on Windows. This is a negative platform observation, not a passed
strict qualification or a defect in shipped Windows code.

The downloaded repeat summary has SHA-256
`3b940498ababc68e6ef2d730aeacbbae270e647cafc1b8705cda1b6c0ee2b913`;
only line endings were normalized in the committed copy. All five source
hashes matched the committed probe. Raw dumps were deleted remotely, never
downloaded. The account-right grant was limited to `SeLockMemoryPrivilege`
and removed afterward; the original explicit account-right set was restored
exactly. A fresh SSH token no longer contained the right, and another native
probe then failed closed without emitting success evidence. Independent cleanup
inspection found no probe registry keys, executables or dump directories.

The account grant itself is broader than the probe's token adjustment: Windows
OpenSSH issued a new Administrator token with the right already enabled during
this experiment. It would be inaccurate to claim the temporary grant affected
only one process. No application deployment policy is inferred from this
disposable-host setup, and no persistent grant is left in place.

Changing to an enclave is a different architecture, not a fallback allocation.
Microsoft's [VBS enclave requirements](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/vbs-enclaves)
include enabled VBS/HVCI, supported recent Windows versions, SDK/tooling and
signing prerequisites. The sensitive workload must execute inside that boundary;
ordinary host Rust workers cannot simply dereference it as protected storage.
No enclave implementation, signing setup or Windows admission has been added.
The remaining design decision must not turn these negative results into a
silent weakening of the existing strict contract.

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
