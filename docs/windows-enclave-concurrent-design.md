# Concurrent Windows enclave workers

Status: public-data platform experiment, not a protected ParallelHash API.
The existing single-thread production sessions and release gates are unchanged.

## Observed platform mechanism

A separate development-signed x86-64 image requests five VBS enclave threads.
Four host threads enter four distinct worker slots; each worker publishes its
active bit atomically and waits **inside** the enclave. A fifth, controller call
must observe all four active bits before it releases them. All four return their
unique expected values and join before enclave termination/deletion. The probe
rejects invalid and duplicate slots, premature completion, exhausted work,
incorrect results and completed-slot replay. A failed join forbids deletion;
the outer process timeout contains a stuck diagnostic. No secret input, digest,
protected worker stack or cryptographic implementation participates.

This establishes overlapping admitted calls, not physical-core placement,
speedup, protected multicore hashing or general scheduler availability.
The [source-bound native observation](../assurance/windows-protection-observations/concurrent-entry-20261003.json)
records three matching captures on fresh enclave instances in the local Windows
11 x64 VBS guest. Linked/signed images and raw records are retained outside
`target/`. The temporary development signing certificate/key was removed;
the SDK compatibility warning is retained. The guest used a source-bound
overlay, not a clean exact Git checkout.

Microsoft documents that initialization returns the actual created thread count
in [ENCLAVE_INIT_INFO_VBS](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-enclave_init_info_vbs).
The probe requires exactly five, rather than trusting its request. All entries
use the nonwaiting form of [CallEnclave](https://learn.microsoft.com/en-us/windows/win32/api/enclaveapi/nf-enclaveapi-callenclave);
an entry failure fails the probe. Thread-capacity exhaustion itself is not tested
by this campaign. Development signing does not establish production admission.

## Required protected design

The existing retained adapter and stack trampoline have shared mutable call,
callback and stack-range globals and initialize exactly one enclave thread.
Raising that count is unsafe: workers could overwrite each other's stack bounds,
retained owner and cleanup state. They must not be reused concurrently.

The next implementation must provide:

- Separate bounded worker contexts: each stack range, guard, lifecycle and
  authority belongs to exactly one live slot. Create thread-bound authorities
  on their admitted worker stacks; never move existing authorities across threads.
- Enclave-owned leaf storage with disjoint mutable ownership, cleanup on every
  exit, and publication only after complete leaf success. Intermediate secret
  chaining values must never pass through host buffers or callbacks.
- An enclave-owned plan and generation/leaf identity checks. Completion order
  must not determine root absorption order; duplicate, stale and missing results
  must reject before finalization.
- A controller slot reserved independently of worker slots. Cancellation must
  release and join admitted work before destroying any referenced state. Host
  scheduling/entry failure must never become portable fallback or successful
  partial output.
- Protected, synchronized root reduction after completion, with bounded counters,
  exact leaf cardinality and the existing ParallelHash framing. Distinct worker
  slots alone do not prove algorithm correctness or complete register cleanup.

These are pending implementation requirements, not claims about this probe.
Before public integration, exercise ordering, cancellation, replay, exhausted
budgets, copy/entry failure and cleanup under overlapping calls. Run independent
oracle comparisons and current-image stack/register/dump qualification afterward.

## Per-worker guarded-stack experiment

The [subsequent stack observation](../assurance/windows-protection-observations/concurrent-stack-20261003.json)
uses a separate C/MASM public-marker image. Each of four one-shot slots owns its
stack bounds, marker address, guard protections and completion state. Atomic
admission rejects duplicates; completion publishes observations only after the
frame has returned. The trampoline uses its passed slot pointer, not shared
stack-bound globals. Callback registration is immutable before workers enter.

Four admitted workers overlap in disjoint 64 KiB windows, with separate boundary
pages. Each window is locked before body entry, cleared and read back in full
from outside the window, then unlocked; boundary protections are restored before
return. Each body verifies its distinct marker after peer execution. The host
checks all sixteen payload pages are locked at admission and still locked at
the clear acknowledgement. Three sampled host reads per live admitted window
fail without copying bytes. These samples do not establish whole-image dump
exclusion or protection of arbitrary caller frames.

Native development tests cover all four workers, denial of slot 2, and injected
slot-2 callback failure after locking. The denied worker never enters its body;
its cleanup does not alter peer results. A separately built missing-clear mutant
returns errors, never receives normal unlock acknowledgement, and is rejected
by normal acceptance. Its remaining locks live until enclave/process teardown.
All host worker calls join before enclave deletion, including error handling.

The first run exposed the default process locking limit: after two 64 KiB locks,
other workers failed with Windows error 1453. Final captures explicitly set the
**test child process only** to an 8 MiB minimum / 16 MiB maximum working-set
allowance, verify the actual values, and still require every `VirtualLock` and
working-set observation to succeed. No machine-wide policy changed. Microsoft
documents the connection between the working-set minimum and the
[VirtualLock limit](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock).
Changing the allowance is resource setup, not proof of residency; the individual
lock checks remain necessary. Production API resource budgeting remains pending.

This establishes a **public-marker stack-isolation foundation**, not protected
Rust worker ownership or ParallelHash. Fatal errors, arbitrary unwinding,
register cleanup, trusted-host attacks and whole-image qualification are not
covered. The existing single-thread production adapters are unchanged. Next is
enclave-local leaf ownership and ordered root reduction on these distinct worker
contexts, followed by algorithm/cleanup tests and public integration.

The subsequent [private root/leaf bridge](windows-enclave-parallel-concurrent.md#private-native-rootleaf-bridge)
now executes a bounded fixed-input ParallelHash batch inside five admitted VBS
frames. Its separate observation record must not be read as upgrading this
earlier public-marker experiment, or as completing public multicore integration.

Additional author checks:

```sh
python3 scripts/cryptography/test-windows-enclave-concurrent-stack.py
python3 scripts/cryptography/windows_enclave_concurrent_stack_build.py stack-build
python3 scripts/cryptography/windows_enclave_concurrent_stack_build.py mutant-build --missing-clear-mutant
```

Build and separately development-sign each image. Capture normal/deny/after-lock
modes using `windows_enclave_concurrent_stack.py IMAGE MODE`. The missing-clear
image is a negative control only, never a usable implementation. Source/image
hashes, four native captures, original linked images and signing records are
saved outside `target/`; temporary signing keys were removed.

## Reproduce author checks

```sh
python3 scripts/cryptography/test-windows-enclave-concurrent.py
python3 scripts/cryptography/test-windows-enclave-concurrent-c.py
python3 scripts/cryptography/windows_enclave_concurrent.py probe-build --build
```

The first suite checks orchestration including refusal to delete live workers.
The second compiles the actual C control logic against POSIX atomic shims and
rejects seven compiled mutations. It does not emulate Windows or qualify VBS.
On the development Windows machine, run generated `link.cmd` from the MSVC
enclave environment, explicitly development-sign the image, then pass its DLL
path to `windows_enclave_concurrent.py`. The native parent permits at most 45
seconds per fresh child and records image/source hashes. Never substitute a
synthetic observation for secret-owner or production-signature qualification.
