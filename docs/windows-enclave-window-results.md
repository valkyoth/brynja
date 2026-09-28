# Windows OS-stack window experiment

Status: synthetic mechanics only, **not strict qualification**. Windows strict
constructors remain Unsupported. No production crypto, dependencies or release
rules changed. This follows the failed
[separate-stack experiment](windows-enclave-stack-results.md); it does not
rehabilitate that trampoline.

## Tested mechanism

The public-marker image at commit
`17531ec31b8cfbf94c21bd6875892d458e15c24a` stays on the OS-managed enclave stack.
A frame-pointer-based assembly function probes 64 KiB with `__chkstk`, reserves
that region below its fixed frame, and initializes it with public marker bytes.
It then calls one fixed C body near the region's top. No arbitrary callback,
host-supplied data pointer or TEB modification is involved.

That body calls a second function with a 256-byte local marker array. In exception
mode the second function raises one exact synthetic SEH exception, clears its
local array in `__finally`, and unwinds to a handler **inside** the window. The
body returns normally to the assembly function. Addresses of both live local
objects must lie wholly inside the window and must not overlap.

After return, assembly lowers RSP to cover the complete region before clearing
and reading back every eight-byte word. It makes no helper calls during that
clear/readback loop. Only then does it restore the fixed frame and return. This
avoids treating memory below the current RSP as a persistent red zone.
Microsoft documents the relevant [stack allocation rules](https://learn.microsoft.com/en-us/cpp/build/stack-usage?view=msvc-170)
and [stack probing/prolog rules](https://learn.microsoft.com/en-us/cpp/build/prolog-and-epilog?view=msvc-170).
Following these ingredients is not by itself proof of a production ABI contract.

## Native results

The Azure development host remained on Windows Server 2025 build 26100.33438,
native AMD x86-64, VBS/HVCI running, test signing enabled and Secure Boot disabled.
The normal and missing-clear images have distinct hashes in their records.

| Mode, three repetitions each | Required outcome observed |
| --- | --- |
| [Normal](../assurance/windows-protection-observations/window-normal-17531ec3.json) | Work markers 31; whole-window zero check succeeds; result 95 |
| [Synthetic exception](../assurance/windows-protection-observations/window-unwind-17531ec3.json) | Exact exception caught, local finally executed; markers 47; whole-window zero check succeeds; result 111 |
| [Missing-clear normal](../assurance/windows-protection-observations/window-mutant-normal-17531ec3.json) | Work markers still 31, but whole-window zero check rejects with result zero |
| [Missing-clear exception](../assurance/windows-protection-observations/window-mutant-unwind-17531ec3.json) | Exception/array cleanup still gives markers 47, but whole-window zero check rejects with result zero |

The mutant removes the assembly clearing loop, not the readback check or local
array cleanup. Its rejection therefore distinguishes complete-region clearing
from clearing only the explicit array. Running the mutant as a normal image and
the normal image as a mutant both fail, with the two
[wrong-mode](../assurance/windows-protection-observations/window-wrong-mutant-17531ec3.err)
[transcripts](../assurance/windows-protection-observations/window-wrong-normal-17531ec3.err)
retained. These are expected failures, not failed results relabeled as passes.

Seven focused Python tests passed locally and natively. They exercise exact
markers and bounds, mode confusion, incomplete/false claims, crashes/timeouts,
setup/teardown errors and the synthetic source contract. They are orchestration
regressions, not a substitute for native machine-code execution.

## Records and limitations

The [build](../assurance/windows-protection-observations/window-build-17531ec3.txt),
[signing](../assurance/windows-protection-observations/window-sign-17531ec3.txt),
[run exits](../assurance/windows-protection-observations/window-run-17531ec3.txt)
and [first-party emitted frame excerpt](../assurance/windows-protection-observations/window-frame-17531ec3.txt)
are retained alongside exact build/sign/run helpers. The frame excerpt includes
the complete clearing/readback loops and RBP unwind metadata. The signing wrapper
failed on compatibility-warning exit 2 and removed the ephemeral identity; the
produced images were deliberately used only for this development experiment.
All nine recorded source hashes were checked against the exact capture commit.

The [post-run observation](../assurance/windows-protection-observations/window-cleanup-17531ec3.json)
found no retained probe process, temporary signing certificate, copied executable,
dump directory or app-specific WER key. No crash dump was collected. Raw download
archive SHA-256: `5d3ca7db21fa6a3ee5db922a5918fd6dd198d054f488a815dd8802ec0d734c8d`.
Full raw disassembly SHA-256:
`47721c9498584ba158df2f55a323b7100c87e9bf41f8ddd3f4607bc43161f23b`.
The full dump remains with the experiment; only the first-party excerpt is
committed. Record/transcript CRLF and trailing whitespace were normalized.

This experiment does **not** establish any of the following:

- Locking before secret entry, residency during work, or independent guards at
  the window bounds. The 64-KiB region is not an enforced call-depth limit.
- Absence of other runtime/TLS, exception-dispatch or register copies outside
  the region. Observing two local addresses does not inventory a whole call tree.
- Unwinding across the assembly frame: the exact tested exception is caught
  inside it. Other faults are not converted into successful observations.
- Rust panic handling, arbitrary closures, concurrency, full worker cleanup,
  dump exclusion for this layout, production signing or Windows Arm support.

Next: prototype pre-secret host/enclave residency admission while the window is
live, then enforce its bounds and failure cleanup. Do not import the previous
separate-allocation locking result as proof for this stack window. Production
integration remains blocked until the complete contract is demonstrated.
