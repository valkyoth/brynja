# Retained enclave result ownership experiment

Status: **isolated lifecycle model, not native protected-storage qualification or
a shipping Windows API.** Production code, dependencies and release gates are
unchanged. Only public diagnostic values are used in the tests.

## Why a separate owner is necessary

The current guarded worker clears its complete 64 KiB window before returning.
Retaining an address into that window would retain erased/reusable stack storage,
not a result. Retained output must instead belong to a separate allocation whose
residency lasts across worker calls. No host slice may expose enclave-private
memory, and a public routing token must not outlive the actual enclave owner.

The first bounded design uses one 32-byte result slot per instance. A live slot
rejects a second fill instead of overwriting an unconsumed result. General slot
pools, arbitrary-size outputs and concurrent workers are not part of this model.

## Executable lifecycle model

[`persistent_result.rs`](../assurance/windows-enclave-probe/persistent_result.rs)
borrows storage independently from a worker frame. Moving the metadata owner does
not move its backing bytes. Its states are idle, busy, ready, quarantined and
closed. A checked monotonic generation and two-word instance identity accompany
the fixed slot number. Generation exhaustion quarantines rather than wrapping.
The eventual adapter must generate instance identity itself; this model accepts
explicit test identities and does not authenticate tokens.

A successful fill is the only transition that retains bytes. A ready result
persists until export, cancellation, explicit closure or owner destruction.
Every export/cancel attempt is terminal for that result, including malformed
identity, stale generation, wrong slot and absent public-output acknowledgment.
Partial fill/copy failure, unwinding and unknown completion clear the slot and
quarantine it. Failed public copy-out may already have changed part of the
**public** destination; no transactional copy-out guarantee is claimed.

The model has no secret byte-view API, allocation, raw pointers or unsafe code.
Its fill/copy closures are trusted test seams, not proposed application callbacks.
The real adapter must bind these to fixed in-enclave operations and OS copy-out.
The native digest implementation must write into independently resident storage;
the synthetic fill tests do not prove that integration or compiler spill cleanup.

Dropping a public token does not own or clear the underlying slot; the instance
owner remains responsible. A forgotten token leaves a bounded busy slot until
explicit cancellation or instance teardown. Forgetting the owner itself bypasses
Rust Drop, as does fatal abort; this model makes no cleanup claim for either.
Native teardown must not rely on host token Drop as its only storage owner.

## Tests

```text
python3 scripts/cryptography/test-windows-enclave-persistent-result.py
```

Six Rust tests run at O0 and O2, covering retention after a synthetic worker frame
is cleared, metadata movement, exact single-use output, busy rejection, stale and
cross-instance tokens, partial writes, both unwind paths, cancellation, abandonment,
closure and generation exhaustion. Four compiled regressions (missing clearing,
reused generation, ignored token, implicit public export) must fail at both levels.
A positive consumer and eleven compiled negatives check exclusive storage
borrowing, nonescaping callback references, private fields and absence of
Send/Sync/Copy/Clone/Debug. These are lifecycle tests, not native residency evidence.

## Native storage experiment and remaining integration

Microsoft lists VirtualAlloc, VirtualFree, VirtualProtect and VirtualQuery among
the APIs available inside VBS enclaves. That list alone does not demonstrate
guard-page or residency behavior on our image and host.
[Microsoft Vertdll API list](https://learn.microsoft.com/en-us/windows/win32/trusted-execution/enclaves-available-in-vertdll).

The [separate public-marker image](windows-enclave-persistent-slot-results.md)
now exercises allocation, guarded retention and clear-before-release. It is not
yet connected to this Rust model or cryptographic results. The integration
obligations remain:

1. Allocate or reserve an independent page-aligned slot with two guard pages;
   verify its address lies inside the enclave and outside the worker window.
   Acquire and verify residency before storing any marker/result.
2. Return from the worker, verify the worker window was cleared, and access the
   same slot through a later worker call while residency remains acquired.
   Reject failed acquisition and overlapping/reused storage without a ready slot.
3. Clear/read back the complete owned data allocation while it remains locked,
   then release it. Exercise cancellation, forgotten public token, failed copy,
   uncertain completion and teardown failure (these integrated cases remain
   pending). Bind observations to the new image;
   do not reuse the older worker's dump observation as proof for this allocation.

Only after those controls work should the adapter add an affine host result
handle retaining the enclave owner, fixed in-enclave composition and explicit
public export. Development signing and full runtime coverage remain separate
requirements; Windows strict remains unavailable.
