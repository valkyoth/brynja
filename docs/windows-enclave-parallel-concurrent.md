# Private concurrent ParallelHash component

Status: safe-Rust component tested in ordinary Linux and Windows processes;
a separate private fixed-input bridge now executes inside native VBS with
distinct admitted root/leaf windows. **Neither is a shipping multicore API or
native secret-processing qualification.** Production APIs and gates are unchanged.

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

The private bridge below places the bounded root/slots on an admitted root frame
and runs leaves on the [distinct guarded stacks](windows-enclave-concurrent-design.md).
Arbitrary-input copying, multi-wave schedules, cancellation across actual enclave
calls, supported public host integration and current-image cleanup/dump
qualification remain pending. The earlier synthetic stack experiment and ordinary
process tests alone must not be combined into a protected-execution claim.

## Private native root/leaf bridge

`parallel_concurrent_bridge.rs` is a separate unsafe FFI adapter, not part of the
safe component or shipping crates. The image uses five enclave threads: the root
call remains live on its original admitted 64 KiB window, while a host dispatch
callback starts four leaf calls with independent admitted windows. The root
constructs its authority on that same thread and checks that the plan, batch
and authority addresses lie inside its live window. Leaf authorities are created
on their own threads. CVs remain in root-owned enclave slots, never host buffers.

One atomic word binds admission, permanent per-lane claims, active borrows and
successful completion. Publication is release/acquire; each worker obtains a
unique ticket before loading its slot pointer. Closing admission and claiming a
slot race on the same word. The root independently waits for all tickets to be
released before reducing or dropping the batch, even if the host returns early
or falsely reports success. Pointers are erased before root reuse/destruction;
each image permits only one batch, avoiding generation/ABA reuse. An exhausted
join budget is process-fatal, never permission to free live borrowed storage.

The baseline C boundary validates AVX2 and OS vector-state support before each
Rust body. Its rejection latch is atomic in this concurrent image. The retained
single-thread image and its nonconcurrent state are not reused concurrently.
Deployment/migration guarantees remain required; these checks are not a scheduler
lock. Page residency uses the existing trusted-host lock acknowledgement and
page checks, not a claim that an adversarial host cannot revoke a lock.

The [native bridge record](../assurance/windows-protection-observations/parallel-concurrent-bridge-20261003.json)
covers four fixed public oracle fixtures: ParallelHash128/256 and both XOFs,
128 input bytes, B=32, empty customization and 512 output bits. Actual VBS calls
verify ordered reduction against the independent oracle. Four leaves and the
root occupy five disjoint guarded/locked windows. Whole-window zero/readback
precedes unlock; guards are restored; sampled live host reads reject without
copying data. This establishes overlapping enclave calls, **not simultaneous
instruction execution on five physical cores or a throughput claim**.

Additional native cases reject a denied leaf, a denied root, a missing leaf and
a host claiming success without starting work. Ordinary-process bridge tests
also force an early host return while four workers still borrow slots. Six
compiled atomic-protocol mutants must fail actual tests, not compilation.
Evidence regression tests reject missing frames, page observations, cleanup,
overlapping windows, early root finish and unsupported qualification claims.

This is a development-signed, public-fixture experiment. Arbitrary host inputs,
streaming waves, supported API ergonomics, complete compiler/register/spill/dump
qualification and independent review remain outstanding. Fatal termination is
not a successful cleanup path. The existing 8/16 MiB test-child working-set
allowance remains explicit; no system-wide memory policy is changed.

Author checks (build requires native AVX2, image linking requires Windows MSVC):

```sh
python3 scripts/cryptography/windows_enclave_parallel_concurrent_image.py bridge-build
python3 scripts/cryptography/test-windows-enclave-parallel-bridge.py bridge-build
python3 scripts/cryptography/test-windows-enclave-parallel-concurrent-native.py
```

Use `--image` on the builder for Windows, run its `link.cmd`, and separately
development-sign the diagnostic image. Run `windows_enclave_parallel_concurrent_native.py
SIGNED_DLL OUTPUT_JSON` for eight bounded fresh-process cases. No signing key is
retained. A Windows mutation-runner newline restoration failure was corrected by
restoring exact original bytes; failed and superseded artifacts remain available.

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
of an exact clean Git checkout. That component record claims no independent review
or VBS execution; the later private bridge has its own separate native record.
