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

The first useful host is native Windows x86-64 with Administrator SSH access,
a current supported Windows SDK and the selected Rust MSVC toolchain. Request
it once runnable probes are prepared, so it need not sit idle during design.
Native Windows AArch64 must be qualified separately before claiming that lane;
Linux Arm, cross-compilation and emulation are not substitutes.

Caller-owned inputs, application-created copies, privileged snapshots,
hibernation and fatal abort remain documented limits. Passing a probe or a
functional test is not independent cryptographic review or certification.
