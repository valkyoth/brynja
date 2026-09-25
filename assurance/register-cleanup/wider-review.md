# Wider caller/worker review — v0.24.49

Updated 2026-09-25. This completes the second author-review work item after the
[KMAC verifier composition review](kmac-review.md). It is **not an independent
retest, release receipt, native platform qualification, or whole-API erasure
proof**. F1 remains open pending guarantee/coverage reconciliation and retest.

## Result

The cross-family source review, focused lifecycle/transfer regressions, fresh
caller diagnostics, and actual worker MIR/LLVM handoff review completed without
finding a new production defect. No production Rust changed in this pass.
The only collector change stores new diagnostics under ignored `dist/`, rather
than Cargo's disposable `target/`; it has a focused regression test.

The review distinguishes three different obligations:

1. Kernel/transfer normal-return working-register cleanup, checked at the
   declared opaque assembly boundaries.
2. Caller-owned storage, borrowed handoffs, destination cleanup and destructor
   dispatch, checked through source review, runtime mutations and emitted code.
3. Whole-call/compiler/platform coverage, which must not be inferred from the
   first two and remains the next qualification work item.

In particular, a zero input-marker count is only a negative observation. It does
not detect every transformed intermediate or prove that an arbitrary spill,
caller-preserved register, thread runtime, signal frame or platform snapshot is
erased. No new release gate, full-sweep requirement or backend admission changed.

## Family review

| Family | Reviewed boundary and disposition | Fresh focused validation |
| --- | --- | --- |
| SHA-2, including general SHA-512/t | Scoped workspaces initialize public IVs before input; handles borrow the owner. Updates commit reuse only on success. Finalization guards secret destinations and uses opaque payload copies/masks. Scalar fallback and batch packing remain separate kernels. Public release is explicit declassification, not a secret-output cleanup promise. | Portable, named/general execution and native SHA-NI lifecycle/transfer tests; 104 compiled mutants rejected; packaged consumer covers six named identities and all 510 general parameters. |
| SHA-3/SHAKE/cSHAKE | Borrowed sponge absorption, partial-byte handling, padding, staging and reader transfers use the matching copy/xor/mask boundaries. Scope/operation guards cover errors, forgotten handles and recoverable unwind. XOF transfer moves a borrow, not the populated sponge. | 146 compiled portable/AVX2 framing, prefix, reader, cleanup and authority mutants rejected; packaged consumers pass. Shared reader details retain the separately scoped KMAC review. |
| Legacy SHA-1 | Portable and accelerated engine copies borrow input/state/output; partial-bit masks do not materialize a secret byte as a caller scalar. Independent scope/operation/handle cleanup remains distinct from hardware authority and public length accounting. | 16 compiled portable/accelerated-engine transfer/padding mutants rejected, debug/release. Native caller suite also checks baseline scalar SHA-1. |
| Legacy MD5 | Portable engine and eight-lane scoped batches keep active owners in final storage. Public IV reset precedes input. Request rejection preserves executor reuse; backend failure/unwind retains quarantine. Output transfer and SIMD-to-scalar tails retain their original clearing owners. | 8 portable and 8 native AVX2 batch transfer/padding/eligibility mutants rejected, debug/release. |
| TupleHash | The scoped core keeps pending/staging bytes in clearing metadata. Partial-item packing borrows bytes into the xor primitive. Item lengths/framing remain metadata; terminal/final-bit secret-output failures clear destinations. Reader transfer moves only borrowed handles and their cleanup guard. | Portable and accelerated four-identity caller probes, independent vectors, output-owner and revocation controls; higher-caller mutation campaigns pass. |
| ParallelHash | Leaf/root states remain distinct. Fixed/XOF suffixes, incomplete collection rejection and exact plan/order binding remain enforced. Streaming buffers and leaf CVs have clearing owners. Scheduled and batched results transfer secret-output loans, not live authority or populated workspace values. | Portable, accelerated and threaded four-identity probes; coordinator cancellation/order/route/output-owner mutations; actual worker MIR/LLVM checks described below. |

The higher-caller campaigns reject 10 portable and 16 accelerated compiled
regressions in total across debug/release. The threaded coordinator campaign
rejects another 16. These counts are separate from the primitive-family counts
and from interpreted MIR/LLVM mutations.

Source inspection also checked apparent ordinary copies: public IVs, explicit
declassification, declared length/shape/counter metadata, test-only probes, and
the safe scalar models selected for other architectures/Miri/Kani. These are not
silently described as secret payload register cleanup. The old movable APIs
remain supported with their existing compiler-copy/spill limitations.

## Actual worker handoff and return

`check_worker_handoffs.py` checks the actual single-leaf and batch worker MIR,
not the coordinator after `join`. Sixteen single-leaf and sixteen batch
functions preserve direct workspace borrows, with destructor dispatch on return
and recoverable-unwind paths. The parent `GroupSlots` destructor forwards its
own receiver to clearing in all eight configurations. Its allocation is made
empty and is not resized after secret CVs populate it; worker loans are disjoint.
All started workers are joined even after a failure, and merge order is submission
order. A forgotten completed-result loan does not bypass the parent's guard.

The new `check_worker_llvm.py` additionally examines the actual emitted worker
bodies: 48 functions, 144 cleanup-dispatch sites and 96 return/resume exits.
These include optimized closures inlined into the thread backtrace wrapper.
After the secret execution invocation, workspace uses are restricted to their
original cleanup receiver, the reviewed batch subfield and lifetime termination.
Loads, stores, aggregate copies, pointer escapes and unknown workspace callees
reject. Actual execution and cleanup targets must have retained definitions.
All 896 LLVM regressions reject; 48 normalization controls pass.

This is a **cleanup-dispatch and handoff check**, not a proof of an opaque
callee's behavior or of destructor completion if that destructor itself panics.
The single-leaf source cleanup reaches XOF storage, engine memory, output stage
and session scratch. Batch cleanup reaches the SHA-3 batch workspace, leaf-value
slots and staging, with field destructors afterward. The corresponding existing
runtime cleanup tests and primitive assembly checks are separate evidence.
Double-panic/abort paths are not claimed to erase anything.

The existing MIR regressions also pass: 256 single-leaf and 368 batch mutations,
24 parent-slot mutations, and six record-validation regressions per worker mode.
The fresh actual production assembly passes 88 scalar/copy/mask/xor/predicate/
comparison boundary inspections and 16 single/batch Keccak inspections. Sixteen
actual Keccak batch transpose bodies also pass the existing transfer inspector.

## Retained local evidence

Each record contains the exact source closure, full compiler identity, flags,
artifact hashes and eight rows: Rust 1.90.0/1.98.1 × debug/release × native Linux
x86-64/emulated Linux AArch64. Arm uses QEMU and is **not native evidence**.
Collection used the production tree at `f5514013` plus the recorded collector/
test change; no commit identity substitutes for the captured byte hashes.

| Profile | Local record under ignored `dist/` | Record SHA-256 |
| --- | --- | --- |
| Scoped primitives | `caller-residue-aw0701he/observations.json` | `4202ed03f37b67d9fe153595b025ed3c102cf186558fa9116df05cc0cb01cda5` |
| Portable higher constructions | `caller-residue-holkq_gq/observations.json` | `bde69a86fb6f7464f065e11fad0a759a2e25e12070776084983738a397e51d59` |
| Accelerated higher constructions | `caller-residue-5rxqvlnf/observations.json` | `8cf02cc688ca313dea393ac2b278bb32cc6eb6cc4a29a3f2a8ae7487c7713b76` |
| Threaded coordinator and worker artifacts | `caller-residue-6onorj0g/observations.json` | `e81723b3061221e05dfad704614815d364dab53a457d0688da9d3ccda61bfc1d` |

All observed input-marker counts are zero: 1,120 primitive, 2,688 portable
higher, 2,688 accelerated higher, and 1,728 threaded-coordinator observations.
Their records explicitly retain `qualifies_register_cleanup: false`.
The worker evidence comes from the separate emitted-code inspections, not those
1,728 coordinator observations. Old `target/` evidence was lost to Cargo clean;
these are fresh captures, not assertions that missing artifacts still exist.

Collection logs are `dist/wider-{scoped,higher,accelerated,threaded}-collection.log`.
Focused regression logs are `dist/wider-sha2-regressions.log` and
`dist/wider-sha3-legacy-regressions.log`; retained-boundary inspection output is
`dist/wider-existing-boundaries.log`. The earlier KMAC record and its matching
checkout remain separate, unchanged, and subject to their own strict hashes.

## Reproduce without recompiling

```sh
record=dist/caller-residue-6onorj0g/observations.json
python3 assurance/register-cleanup/check_worker_handoffs.py "$record"
python3 assurance/register-cleanup/test_worker_handoffs.py "$record"
python3 assurance/register-cleanup/check_worker_handoffs.py --batch "$record"
python3 assurance/register-cleanup/test_worker_handoffs.py --batch "$record"
python3 assurance/register-cleanup/check_worker_llvm.py "$record"
python3 assurance/register-cleanup/test_worker_llvm.py "$record"
python3 assurance/register-cleanup/check_recorded_boundaries.py "$record"
python3 assurance/register-cleanup/check_recorded_keccak.py "$record"
```

The next work item is the explicit compiler/target/ABI/feature guarantee matrix
and stable pentest handoff. Native Windows/macOS/Arm evidence, independent retest
and final approved release verification are still separate. Do not mark F1
resolved, delete root `PENTEST.md`, or claim whole-process/military/FIPS assurance
based on this author review.
