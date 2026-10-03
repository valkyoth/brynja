# Private concurrent ParallelHash component

Status: safe-Rust component tested in ordinary Linux and Windows processes;
a separate private fixed-input bridge now executes inside native VBS with
distinct admitted root/leaf windows, including the bounded three-wave experiment
below. **Neither is a shipping multicore API or
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
  XOF reader is implemented here. `Batch` is single-wave; the separate private
  `Waves` component below retains a root across successive bounded waves.
- Normal typed clearing does not prove complete frame/register/spill erasure.
  Caller copies and ordinary-process storage are not protected by this component.

The private bridge below places the bounded root/slots on an admitted root frame
and runs leaves on the [distinct guarded stacks](windows-enclave-concurrent-design.md).
Arbitrary-input copying, multi-wave enclave dispatch, cancellation across actual enclave
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

## Private multi-wave component

`parallel_concurrent_waves.rs` adds a safe `no_std`, fixed-storage root scheduler
for all four ParallelHash identities. It reuses the same accelerated state and
leaf implementation; no permutation, unsafe code or external dependency is added.
It is **not yet connected to the native multi-call bridge or a shipping API**.

The root fixes the total message length, B, customization and output length at
construction. It absorbs the cSHAKE prefix and B once, then owns the next byte
offset and the expected global leaf count. Each operation creates a fresh scoped
plan and at most four exclusive slots. The internal scheduling callback can run
those slots on scoped workers, but cannot retain them, re-enter or destroy the
borrowed root, or manufacture a second batch with the same plan. The native FFI
adapter must provide equivalent lifetime guarantees; safe Rust callbacks alone
do not prove raw-pointer or OS-call safety.

Successful waves absorb CVs in canonical order, clear each consumed slot and
commit checked global counters. Missing, reordered or replayed slots, callback
failure, cancellation, revocation and unwind make the root terminal and clear
its state/output. Finalization requires **both exact total-bit completion and
the exact global leaf count**, then encodes the count and fixed/XOF output suffix
once. Public export is transactional and clears retained bytes. Caller-owned
inputs remain outside this component's ownership/erasure guarantee.

Bounds remain explicit: B is 1–1024 bytes, at most 65,536 leaves, customization
and terminal output at most 8192 bits, and only four CV slots per wave. Storage
does not grow with the message. These are private prototype bounds, not a new
production API contract. Shape/offset/count information is public metadata.

The [multi-wave component record](../assurance/windows-protection-observations/parallel-waves-component-20261003.json)
records ordinary native-process tests on Linux and Windows x64 AVX2:

- 532 oracle cases in reverse and real scoped-thread order: 1,064 comparisons
  per platform, including bit tails, empty input, wave boundaries, 128 leaves,
  1024-byte blocks and all twelve retained NIST samples via the independent oracle.
- The existing 380-case bounded-component campaign remains in the same binary.
- 21 tests include cancellation racing workers at each wave boundary, exact
  completion/counter corruption, output transactionality, revocation and unwind.
- Fourteen compiled runtime mutants and eleven compiled ownership/API negatives
  are rejected. Mutants must compile; compile failure is not a runtime rejection.
- Library and test Clippy pass locally with the existing compatibility allowance.

```sh
python3 scripts/cryptography/test-windows-enclave-parallel-waves.py waves-check
```

The builder creates a separate generated crate root adding the wave module; it
does not edit the existing bounded component or its prior native bridge. Sources,
generated files and restored mutation inputs are hash-checked. Windows uses
source-bound overlays, not an exact clean-checkout claim. Production interfaces,
release gates, protected-stack admission and signing are unchanged by this step.

Next: integrate successive waves into the enclave transport with checked
publication generations, stale/replayed call rejection and join-before-reuse
for every worker window. Then implement arbitrary-input copy/admission and the
supported public interface, followed by current-image cleanup qualification.
Do not reset the existing one-shot gate or reuse raw pointers merely because
the host reports that a previous wave finished.

## Generation-bound multi-wave adapter (process tests only)

The private `parallel_wave_gate.rs` and `parallel_wave_bridge.rs` now connect
the wave scheduler to an FFI-shaped worker boundary in **ordinary native
Linux/Windows processes, not native multi-wave VBS calls**. They do not replace
the earlier one-shot enclave image. No shipping API or release gate changes.

The gate binds a nonzero, monotonically increasing generation, active lane mask,
permanent claims, live tickets and success bits in one atomic word. Old/future
generations, inactive lanes and duplicate calls reject before loading a slot
pointer or its shape. Publication uses release/acquire. Closing admission races
worker claims on the same word; a closed wave cannot reopen, including when no
worker entered. Generation exhaustion fails closed rather than wrapping.

The thread-bound root lease permits retirement only after closing admission and
observing every worker's final release. Retirement is an explicit adapter
acknowledgement: **the gate itself cannot prove storage clearing or pointer
lifetimes**. Dropping a non-retired lease seals the gate, including on unwind.
The adapter independently joins, erases published pointers and metadata, and
waits for typed reduction/slot cleanup before allowing the next generation.
Worker authorities remain worker-local; the original root authority stays live
on its creating thread for all three waves. CVs are never host-relayed.

The [generation-adapter record](../assurance/windows-protection-observations/parallel-wave-bridge-20261003.json)
records Rust 1.98.1 native AVX2 process checks on both platforms:

- Ten gate tests, including competing roots, close/claim races, live-ticket
  retirement rejection and delayed requests during the next open publication.
- 64 identity/fault cases: four ParallelHash identities; three waves/ten leaves
  with a three-bit final leaf; normal execution, early host return, missing/empty
  work, cancellation and internal Rust unwind at each wave boundary.
- Fifteen gate and four adapter compiled runtime mutants rejected by failing
  tests, not compilation errors, crashes or timeouts; nine compiled ownership,
  private-field and lifetime rejections. Focused local Clippy passes.

Inputs and results are fixed **public oracle fixtures**. The ordinary-process
region-check stub does not establish enclave placement or protection. Root
unwind is tested through a private Rust entry, never by unwinding across C ABI.
Fatal abort and a nonreturning worker are not successful cleanup paths; an
exhausted join budget terminates rather than freeing a borrowed root.

```sh
python3 scripts/cryptography/windows_enclave_parallel_wave_bridge_build.py wave-bridge
python3 scripts/cryptography/test-windows-enclave-parallel-wave-bridge.py wave-bridge
```

The native experiment below separately binds generation contexts to C/MASM
worker windows for its fixed fixture. A Rust ticket release alone does not prove
completion of the enclosing C/MASM stack cleanup. Arbitrary host-input copying,
public API integration and current-image register/spill/dump qualification remain
pending.

## Private native three-wave experiment

`windows_enclave_parallel_wave_image.py` links the unchanged tested Rust adapter
with a separate C/MASM image. The original root call and authority remain on the
same admitted 64 KiB frame across three waves. Four worker entries are available;
the final wave uses only two. The image has one operation and three distinct,
never-reset native gate records, with separate diagnostic slot metadata for each
generation. This is **not a general reusable-image or arbitrary-length API**.

Public worker contexts carry generation/lane, never pointers. Native admission
rejects unopened future waves, closed old waves, inactive lanes and permanent
duplicate claims before accessing a slot. Each native ticket outlives the Rust
worker call: its last release follows whole-window assembly clear/readback,
trusted-host unlock acknowledgement, guard restoration and final metadata writes.
The root independently closes admission and waits for these native releases
before returning from dispatch to Rust, which then independently joins its own
slot tickets and completes typed reduction/clearing before retirement.

The host's early-return experiment holds workers inside admission callbacks,
returns success without joining, and releases them only after an explicit native
close notification. The root still waits for their cleanup. Later waves may use
the same OS-managed stack addresses, but never simultaneously reuse live windows
or reset prior claims. Host thread joins and per-wave page/cleanup observations
are recorded before continuing. An exhausted native join budget terminates the
process; it never authorizes releasing live storage.

The [native three-wave record](../assurance/windows-protection-observations/parallel-wave-native-20261003.json)
records 17 real Windows 11 x64 VBS cases: four normal ParallelHash identities,
denied admission, dishonest empty success, missing work and early return at each
of the three waves, plus root-admission denial. Normal inputs are fixed public
fixtures (2307 bits, B=32, empty customization, 512 output bits); the result is
compared to the independent oracle inside the enclave. Every case checks stale,
future, duplicate and post-close rejection. Successful overlapping windows have
complete page-lock observations and three rejected host-read probes per frame.
This demonstrates overlapping enclave calls, not five physical cores or speedup.

The first denial campaign exposed an orchestration mismatch: a denied entry
could finish before all peers entered, allowing legal OS stack reuse within a
wave. The final host barrier includes denied admissions, and a regression now
requires all admissions before any finish in each denied wave. The strict
disjointness check was retained; all 17 native cases were rerun. Six host/evidence
tests and ten compiled native-gate mutations using POSIX atomic shims also pass;
the latter are explicitly not Windows/VBS proof.

```sh
python3 scripts/cryptography/test-windows-enclave-parallel-wave-native.py
python3 scripts/cryptography/test-windows-enclave-wave-native-gate.py
```

Build the image on Windows with `windows_enclave_parallel_wave_image.py`, run
its `link.cmd`, development-sign a separate copy, then run
`windows_enclave_parallel_wave_native.py SIGNED_DLL OUTPUT_JSON`. Final artifacts
and 287 source bindings are saved locally outside `target/`. The temporary
development certificate/private key was removed; the SDK compatibility warning
is retained. No production-signing, independent-review, arbitrary-unwind or
whole-image cleanup qualification is claimed. Production crates, API defaults,
dependency versions and release gates are unchanged.

Next: arbitrary-input admission/copying and the supported public host scheduling
API, followed by current-image ABI/register/spill/dump qualification. The fixed
three-wave diagnostic is not a substitute for these remaining steps.

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
