# Private concurrent ParallelHash component

Status: safe-Rust component tested in ordinary Linux and Windows processes.
**Not a shipping API, enclave execution, protected-memory admission or native
secret-processing qualification.** Production APIs and release gates are unchanged.

## Implemented boundary

The component reuses the existing accelerated cSHAKE/SHAKE state adapter and
hardened Keccak engine. It introduces no permutation implementation, unsafe
code, manual `Send`/`Sync`, external dependency or host callback in its normal
execution path.

A plan fixes the ParallelHash128/256 or XOF identity, B, message/customization
bit lengths and output length. These are **public metadata**; this API does not
hide batch shape. A plan can be claimed only once, including after its batch is
dropped. Exact plan identity and leaf index bind every completed slot.

The root owner remains thread-bound and borrows its original root authority.
Exclusive leaf slots can be borrowed by scoped workers. Each worker constructs
its own authority on that worker; authorities never move across threads. Slots
have no public CV accessor and are neither `Copy`, `Clone` nor `Debug`. Slot
storage is transferable for scoped ownership, not a protected-memory primitive;
all storage, references and call frames still require separate enclave placement.

The root cannot reduce or be destroyed while mutable worker borrows remain
live. After join it requires every expected leaf to be complete, rejects
foreign/reordered/duplicate/missing slots, and absorbs CVs in message order,
independently of worker completion order. It then appends the leaf count and
fixed-output length or XOF zero suffix. Process tests cover actual threads and
reverse-order leaf computation.

Leaf and root operation guards clear owned output bytes on failure and Rust
unwinding. Consumed CVs are cleared after absorption. Cancellation is one-way;
workers check it before and after hashing, and the root checks before reduction,
before retaining output and before declassification. This is bounded cooperative
cancellation, not interruption of an in-flight permutation. Revocation of the
original root authority prevents output export. An explicit public
declassification operation requires exact destination length and leaves it
untouched on rejection; completion clears the retained batch too.

## Deliberate bounds and remaining integration

- At most four leaves per batch; B is 1–1024 bytes.
- Arbitrary-bit final input and customization; customization is at most 8192 bits.
- Fixed output or a terminal XOF prefix is at most 8192 bits. No incremental
  XOF reader or multi-wave streaming scheduler is implemented here.
- Normal typed clearing does not prove complete frame/register/spill erasure.
  Caller copies and ordinary-process storage are not protected by this component.

Next: place plans, root and slots in admitted enclave storage; construct workers
on the [distinct guarded stacks](windows-enclave-concurrent-design.md); implement
the checked worker ABI and ordered completion protocol; qualify copy failure,
entry failure, destruction and cancellation across real enclave calls. Larger
streaming schedules, public host integration and current-image cleanup/dump
qualification remain pending. The synthetic stack experiment and ordinary
process component tests must not be combined into a claim of protected execution.

## Author verification

```sh
python3 scripts/cryptography/test-windows-enclave-parallel-concurrent.py component-check
```

The [source-bound component record](../assurance/windows-protection-observations/parallel-concurrent-component-20261003.json)
records Linux and Windows x64 AVX2 process results under Rust 1.98.1:

- 12 tests, including cancellation racing four workers and injected unwind after
  computing a leaf/root output but before publishing it.
- 380 independent oracle cases in reverse and real scoped-thread modes: 760
  comparisons per platform. The oracle is separately cross-checked against all
  twelve retained NIST samples; cases outside this component's bounds are not
  silently claimed as component coverage.
- Fifteen compiled runtime mutations and thirteen compiled ownership/API
  negatives rejected. Compilation errors do not count as runtime mutation kills.
- Library and test Clippy pass locally, with the existing compatibility allowance
  and two narrowly explained fixture allowances: inline shared-state enum instead
  of heap allocation, and the test-only independent oracle row helper.

The first Windows mutation run encountered a linker error replacing a recently
executed EXE. The corrected runner keeps a distinct executable for each mutation
and the final clean run; no security setting was disabled. The failed log is
retained. Passing source hashes, generated sources and final binaries are saved
outside `target/`. The Windows checkout uses source-bound overlays, not a claim
of an exact clean Git checkout. No independent review or VBS execution is claimed.
