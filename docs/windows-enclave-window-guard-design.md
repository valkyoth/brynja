# Guarded OS-stack window experiment

Status: **synthetic native boundary controls passed; not strict qualification**.
No Windows strict support is enabled. No release gate, production Rust or
cryptographic implementation changes are part of this experiment.

## Why another image

The [live-window residency probe](windows-enclave-window-lock-results.md) locks
all pages covering its window, but does not independently enforce its boundaries.
The new `window_guard.c` and `window_guard_x64.asm` preserve that earlier image
and its evidence. Their separate native results are recorded
[here](windows-enclave-window-guard-results.md); they do not inherit its pass.

The proposed frame stays on the OS-managed enclave stack. It probes/reserves
alignment slack, a 64-KiB page-aligned payload, two separate boundary pages and
bootstrap shadow space. The enclosing caller frame remains above the upper
boundary; setup and cleanup helpers execute below the lower boundary. Only the
fixed synthetic body executes inside the payload.

The enclave helper first checks both prospective boundary pages are committed
read/write memory, then attempts `VirtualProtect(PAGE_NOACCESS)` on each. It
requires exact post-change observations before asking the existing trusted-host
callback to lock the sixteen payload pages. The documentation lists
[VirtualProtect among enclave APIs](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves-available-in-vertdll),
but that alone does not prove that changing these OS-stack pages is supported.
That question required separate native execution, now recorded for this exact
fixed-body experiment, not arbitrary runtime stack usage.

`PAGE_NOACCESS` is deliberate: [PAGE_GUARD is a one-shot alarm](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualprotect).
The experiment attempts two reads or two writes at the same selected boundary,
accepting only access violations with the exact expected address and access kind.
An unrelated crash, a successful forbidden access, or only one observed fault
cannot count as a passing boundary control. Protection is checked again after
those accesses. No undocumented TEB edits or custom stack-limit override is used.

After the fixed body, assembly clears/readbacks the complete payload while the
host lock remains held. The prior finish handshake may then unlock it. Every
return path separately attempts to restore both changed boundary pages to their
original protection, from the lower bootstrap frame, before the OS reuses them.
Protection restoration is not erasure. A missing-clear image still retains its
payload lock until teardown; it cannot turn restoration into a cleanup claim.

## Local checks and required native controls

Ten focused Python tests pass locally and natively. They cover mode combinations, exact
sixteen-page coverage, two faults per selected boundary, read/write and address
identity, incomplete/false records, callback failures, teardown, crashes/timeouts,
and source ordering. The existing fourteen live-window tests still pass.
These tests use mock APIs and are **not** Windows page-protection evidence.

The following native controls have now been run and
[recorded](windows-enclave-window-guard-results.md):

1. Native `/W4 /WX` enclave compilation, emitted-frame review and development
   signing with warnings preserved, not relabeled as production signing success.
2. Normal return and the existing exact caught SEH exception, with repeated
   execution to detect failure to restore the pages for the next call.
3. Read-low, write-low, read-high and write-high controls, including exception
   mode; two exact access violations each and persistent no-access observations.
4. Host denial, a compiled missing-clear image, a compiled skipped-protection
   image, and deliberately wrong normal/mutant expectations. A setup failure or
   crash is recorded as such, not as a successful boundary result.
5. Download and bind the records to exact sources, toolchain and signed images.

Then investigate actual stack-depth exhaustion and exception-dispatch headroom.
Direct byte accesses to a protected page do not prove that all call-depth
overflows are safely recoverable, that frames cannot skip a page, or that the
runtime never copies state elsewhere. Rust ABI/panics, TLS/runtime ownership,
register cleanup, concurrency, exact-layout dump behavior and production signing
remain separate obligations before production integration.
