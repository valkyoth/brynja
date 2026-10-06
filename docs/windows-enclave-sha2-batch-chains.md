# Windows SHA-2 batch chain review

Status: **partial author review**, completion package 5. The four existing
images are bound, but their complete private lifecycle composition is not yet
closed. This is neither independent retest nor whole-image qualification.
No production code, release gate or native enclave image changed in this pass.

## Bound populations and selected contracts

The frozen inventory covers every emitted Rust body, including cleanup funclets,
and binds the original build inputs, archive members, LLVM IR, assembly and signed
images. SIMD image manifests also bind their underlying worker source manifests.

| Route | Functions (including funclets) | Funclets | Source inputs | Body-byte mutants | Table-byte mutants |
| --- | ---: | ---: | ---: | ---: | ---: |
| Sequential scalar SHA-2 | 32 | 0 | 176 | 16,688 | 336 |
| Sequential SHA-NI | 42 | 1 | 272 | 14,878 | 48 |
| Eight-lane SHA-224/256 AVX2 | 52 | 16 | 258 | 16,562 | 0 |
| Four-lane SHA-512-family AVX2 | 52 | 16 | 260 | 18,757 | 296 |

Actual incoming references, cleanup metadata, constant tables and SDK transport
targets are checked in the linked images. The SIMD cancellation vtables have
exact read-only layouts and absolute pointers to the actual local callback
bodies. Both the closure and its thunk return false without reading input.
The resident constructors install the compiled-target capability function into
the authority; its one-bit private ABI and complete body are checked. This
function is a build-wide capability predicate, not runtime CPU detection or a
migration monitor. Neither callback-target binding nor constructor checking
establishes provenance at every later indirect callsite.

Selected semantic checks cover exact nonwrapping sequence/phase admission,
output clearing on enumerated rejection paths, authority health and revocation,
scalar active-slot and checked budget accounting, and scalar completion
publication only after successful finalization. Private ABI checks retain the
compiler's 1,024-byte sequential input bound and fixed SIMD lane-array sizes.
Constructor failure loops clear all 4,096 backing-page bytes. This does not
claim erasure of constructor stack copies or SIMD live-page retirement.

The sequential scalar and SHA-NI terminal/retirement composition additionally
checks all eight plan entries against their completion bits before sealing.
Export requires the Sealed phase and compares all 64 plan bytes before the
fixed 512-byte copy-out. Copy failure reaches the operation guard; successful
copy-out clears retained output and returns to Empty. SHA-NI rechecks authority
after the copy. Cancellation is admitted only in Collecting, Streaming or
Sealed; selected rejection and success return paths require output erasure.
Incomplete operation guards quarantine the owner (and SHA-NI authority).

Sequential state clearing invalidates the placed enum before destroying the
taken state, including live SHA-NI scratch. All normal worker returns after
buffer construction pass buffer destruction: 128/144 header bytes and 1,024
payload bytes are cleared. Scalar retirement destroys the owner, clears LIVE
and erases the full page; SHA-NI takes the resident out of LIVE, invokes its
destructor and clears the separate page identity. Its destructor destroys the
state and erases all 4,096 backing bytes. These are bounded normal-path checks,
not guarantees for arbitrary OS unwinding, aborts or constructor-stack copies.

The SHA-NI image's two panic-location descriptors bind the actual immutable
filename, length, line and column. This records reachable diagnostic data; it
does not resolve the fail-stop caller preconditions or promise abort cleanup.
Frame sizes, saved vectors and direct reference graphs are recorded, but no
transitive depth bound is qualified while indirect-call composition is pending.

## Reproduced primitives and changed finalizer

The review replays the earlier streaming scalar and SHA-NI semantic checks
against their saved objects and images before permitting reuse. It explicitly
selects fifteen scalar and fourteen SHA-NI helpers and requires complete body,
reference, extent-kind and resolved LLVM ABI equality. Renaming is allowed only
for the scalar `State::finish` definition; its complete local dispatch-table
bytes and relocation offsets must also match. All actual destinations and
constants are rebound in the current images. Other equal bodies are not
implicitly qualified. Batch-specific caller preconditions remain open.

The changed SHA-NI `State::finish` is reviewed separately, not accepted through
body equality. Checks retain its 2,000-byte state and 28-through-32-byte private
output ABI, exact SHA-224/SHA-256 width selection, engine success before output
publication, owner/scratch destruction and 32-byte staging erasure on every
normal return. The batch caller checks active-slot identity, budget, canonical
partial-bit input, eight-slot bounds, 64-byte output stride and success before
completion publication. Its cleanup funclet and the constructor/state-transfer
composition remain open. These checks do not claim individual erasure of
moved-from compiler copies or arbitrary OS-exception cleanup.

## Tests and retained evidence

Thirteen review tests pass on Linux and Windows with matching parsed reports.
They reject 150 semantic-landmark removals, 23 private ABI changes, 25
cleanup-event bypasses, twelve lifecycle and eleven finalizer premature returns,
116 per-helper body/reference/extent/ABI mutations, altered callback layouts/pointers, diagnostic-data drift,
incomplete inventories and inconsistent source closures. The byte-mutation
counts above establish binding durability, not algorithm correctness alone.
Separate regressions reject missing prior semantic reviews, changed dispatch
tables and changed resolved target attributes; an equal unlisted function is
not added to the reused set.

Scoped native Linux component campaigns also pass:

- Scalar: ten component tests, 72 hashlib cases, 255 active-slot masks, 4,080
  general-SHA-512/t bit cases and 26 compiled mutants; one placement test and
  two allocation/lifetime mutants.
- SHA-NI: twelve component tests, 244 independent cases, 255 mixed masks,
  29 compiled mutants and six ownership negatives. Worker tests reject nine
  Rust mutants and nineteen baseline C-gate mutants. Resident tests cover
  242 independent bit cases, 255 masks, three placement mutants and seven
  ownership negatives.
- SHA-224/256 AVX2: 402 independent cases and 3,216 lane comparisons, twelve
  component mutants and six ownership negatives; fourteen worker mutants;
  four resident mutants and eight ownership negatives.
- SHA-512-family AVX2: 602 independent cases and 2,408 lane comparisons with
  the same component/worker/resident mutation and ownership counts as above.

These component runs exercise native SHA-NI/AVX2 on Linux, not Windows enclave
execution or dedicated x86 SHA-512 instructions. Windows replay inspects the
previously saved native images. Inputs remain under
`release-reports/windows-local-20261004/`; reports and component artifacts are
under `release-reports/windows-worker-review-20261006/`, outside `target/`.
The [checkpoint observation](../assurance/windows-protection-observations/sha2-batch-chain-progress-20261006.json)
retains its earlier scope and report hashes. The
[sequential lifecycle observation](../assurance/windows-protection-observations/sha2-batch-lifecycle-progress-20261006.json)
records the extended checks and fresh scalar component, SHA-NI worker and
resident campaigns. The earlier unchanged SIMD campaigns remain applicable;
no product source changed.
The [primitive/finalizer observation](../assurance/windows-protection-observations/sha2-batch-reuse-progress-20261006.json)
records the latest replay and regression scope; it retains those unchanged
component results rather than claiming another native enclave execution.

```sh
python3 scripts/cryptography/test-windows-enclave-sha2-batch-chains.py \
  --saved-directory release-reports/windows-local-20261004
python3 scripts/cryptography/windows_enclave_sha2_batch_chains.py \
  release-reports/windows-local-20261004 --mutate \
  --output release-reports/windows-worker-review-20261006/sha2-batch-reuse-linux.json
```

Without the saved directory the test command runs five self-contained tests
and explicitly skips the eight saved-artifact tests.

## Remaining package-5 work

- Finish batch-specific caller preconditions for the reproduced primitive contracts.
- Complete sequential constructors, state transfers, scalar finalizer callers
  and SHA-NI cleanup-funclet composition; the selected finalizer,
  terminal/export and page-retirement checks above are now in place.
- Complete SIMD callsite provenance, lane-engine/kernel composition and all
  error/cleanup-funclet paths.
- Assign every reachable private frame and storage region, and resolve the
  remaining fail-stop caller preconditions.

Shared runtime, SDK, final platform/depth reconciliation and enclosing-window
reclamation remain package 8 obligations. Nothing here promotes moved-from
copies, compiler spills or incoming register saves to individually erased data.
