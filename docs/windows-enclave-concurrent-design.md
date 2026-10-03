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
