# Saved scheduler clearing-wrapper handoff

This completes the selected normal-return handoff after the
[root cleanup](windows-enclave-root-return.md) and
[SDK output-return reconciliation](windows-enclave-sdk-return.md). The
[observation](../assurance/windows-protection-observations/wrapper-return-20261005.json)
binds the original `PublicStackBody`, `PublicStackFinish`, `PublicStackRestore`
and tested `PublicStackFrame` object bodies to the same signed scheduler image.
Their 1,038 code bytes and complete relocation inventories are checked together.
This remains author inspection, not whole-image or arbitrary-unwind qualification.

## Return and reclamation order

The C body calls the previously reviewed root and carries only its public scalar
result through the common security-cookie check and ABI epilogue. The worker
and early ordinary-rejection paths also converge on that epilogue. The exact
30-byte cookie checker and its zero-frame unwind record are bound: its normal
path preserves RAX and returns; failed cookie checks tail into the fatal boundary
instead. No cookie-failure cleanup guarantee is inferred. The C body's separate
GS exception-handler metadata is bound but not qualified for safe unwinding.

The wrapper preserves the public result in R8, clears XMM0–5 and the selected
volatile GPRs, and conditionally runs `vzeroupper` using the CPU/OS-state decision
made before processing. It preserves the ABI-required low halves of XMM6–15.
This is the existing SSE2/AVX boundary contract, not an AVX-512 or arbitrary
register-capture guarantee.

It then moves RSP below the lower guard and clears all 65,536 bytes in the
admitted work window using 8,192 eight-byte stores. A second loop reads every
word back and ORs them together. A nonzero result skips the finish callback,
selects failure and still attempts guard restoration. Clean readback permits the
finish callback with the public worker result. Both paths converge on restoration.

`PublicStackFinish` marks cleanup complete and requires a successful `CallEnclave`
return plus acknowledgement value one before preserving the worker result;
otherwise it returns failure. The callback receives the public window/lane/phase
metadata, not a payload pointer to live secret work. `PublicStackRestore` attempts
the recorded upper and lower guard-protection restorations, clears their flags
only on success, checks the expected page protections and records its outcome.
Its failure overrides the earlier result. After that callback returns, the
wrapper clears volatile registers again while preserving the public result in
RAX, restores RSP/RBP and returns.

The linked callback and protection calls resolve to the saved named SDK imports.
This does not independently qualify `VirtualProtect`, the page-query helper,
callback implementation, OS faults or protection restoration on fatal exit.
The callback frames run below the cleared window: they are **not** included in
the 64-KiB wipe. Pre-callback register cleanup and public-only callback arguments
are therefore important, not optional explanatory details. Application-owned
nonvolatile state and arbitrary caller copies retain their documented limits.

## Evidence and regressions

Five focused tests pass on Linux and Windows; parsed saved-image reports match.
The actual inspection rejects 1,038 single-byte body mutations per host. Tests
also reject changed branches, relocation identities, cookie instructions,
cookie/global disagreement and wrong unwind metadata. The loop geometry model
checks complete word coverage and translation at three window locations. These
are inspection/model regressions, not fresh native enclave executions.

The existing native public-sentinel wrapper evidence was separately revalidated:
all recorded source/artifact hashes still match, including the exact wrapper
object now bound here. It retains 32 baseline cases, 208 rejected compiled
mutations and 80 passing controls across both wrapper variants. Its record digest
is `7222af475f3d2526d988321b5f5eadf5f44b336613351d3885524dfff6863d31`.
These are reused observations, not another run or independent qualification.

An older combined local checker also attempted to bind historical host-test
sources. That broader check does not pass against today's tree: commit
`598d8dff` updated a bounded-owner test image pin and added a rejection test.
The unchanged wrapper evidence was checked independently; no historical host
campaign was relabeled as current and no gate was relaxed to accept the mismatch.

## Cross-image work remaining

All eighteen current sequential images were rechecked read-only against their
recorded shared-wrapper bindings; they still match. Exact shared wrapper bytes
do not transfer the scheduler's caller/body review to those other images.

| Remaining caller families | Current sequential images |
| --- | ---: |
| Bounded SHA-256 owner | 1 |
| SHA-2 streaming, batch and SHA-256/SHA-512 SIMD | 6 |
| SHA-3 streaming, batch and Keccak SIMD | 5 |
| KMAC | 2 |
| TupleHash | 2 |
| Sequential ParallelHash | 2 |

The subsequent [shared sequential C review](windows-enclave-sequential-c-review.md)
establishes complete byte/reference identity for four common functions across
these eighteen images, including their chained runtime fragments. It binds each
to its own wrapper/imports without transferring the distinct Rust worker reviews.
The next step is their helper and caller/storage reconciliation. The existing
nineteen-image and scoped dump campaigns should not
be repeated for these offline documentation/review changes. Final compiler/SDK
scope reconciliation and independent retest remain; no production code, signed
image, release-gate policy or qualification claim changed in this step.

```sh
python3 scripts/cryptography/test-windows-enclave-wrapper-return.py
python3 scripts/cryptography/windows_enclave_wrapper_return.py SAVED_RUST_OBJECT SAVED_C_OBJECT SAVED_IMAGE TESTED_WRAPPER_OBJECT --mutate
```
