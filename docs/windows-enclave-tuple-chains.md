# Windows TupleHash inner-chain review

This is an **author review of the complete private TupleHash chains**, not
whole-image qualification or an independent retest. Completion-plan step 4 is
closed for the two saved images below. No production source,
public API, release-gate policy or supported-platform claim changed.

## Saved images and reviewed paths

The [reviewer](../scripts/cryptography/windows_enclave_tuple_chains.py) checks
every saved source/build input against the checkout and binds the complete
emitted inventory to the linked image. Bodies, relocations, resolved targets,
extent kinds, immutable constants and indirect-dispatch tables are included.
All six AVX2 cleanup funclets also have their parent-frame reloads, destructor
targets and returning cleanup paths checked. Metadata binding alone is not
treated as qualification, nor is this an arbitrary OS-exception guarantee.
The wrapper and four `PublicTuple*` transport destinations are rebound in each
image. This replay does not build or execute a new enclave.

| Route | Emitted functions | Build inputs | Local stack bound | Binding mutations rejected |
|---|---:|---:|---|---|
| Scalar | 52 | 169 | `H-9712` | 22,808 body bytes; 76 table bytes |
| AVX2 | 55 main + 6 cleanup funclets | 266 | `H-10926` | 23,282 body bytes; 44 table bytes |

The bounds conservatively compose private frames, return addresses, alignment
and constant stack probes. They **exclude shared runtime frames** and are not
maximum whole-image stack bounds. Every emitted body is accounted for by normal
reachability or cleanup metadata; reachability is not semantic qualification.

The checks currently cover:

- Exact item framing: left-encoded bit lengths, checked 128-bit remaining
  lengths, at most 1,024 payload bytes per fragment, remaining-length commits
  only after successful absorption, and exact-zero completion before returning
  from item phase to tuple phase.
- Partial-bit packing: destination offsets below eight, checked pending-bit
  advancement, pending-byte clearing after flush, and the aligned bulk path.
- Final suffix composition: right encoding, fixed versus XOF identity selection,
  rejection of nonzero XOF output lengths, canonical partial tails, and distinct
  reader/retained phase publication. Both strengths enter the reviewed cSHAKE
  squeezing state before output. Fixed output uses a terminal reader, checks its
  result and destroys/disarms the consumed state before publishing retained output.
- Phase admission and checked, nonwrapping exact sequences; accelerated
  admission additionally checks authority health and kernel identity. Reviewed
  rejection blocks and successful cancellation clear the pending byte,
  1,024-byte output and 16-byte remaining count. This does not claim full owner
  allocation or moved-from stack erasure.
- Complete opaque permutation and round-constant checks, including working
  register cleanup. Scalar compilation-local loop labels differ from the prior
  image; only the six explicitly enumerated labels are renamed for comparison.
  Full instruction/branch checks and the original body/image hashes still apply.
- Reproduced KMAC/SHA-3 helper reviews, not copied PASS labels: 24 scalar and
  23 AVX2 helpers match complete body, references, extent kind and resolved LLVM
  ABI. One scalar and four AVX2 renamed helpers have exact explicit bindings.
  Three scalar and four AVX2 ABI-range differences are checked separately:
  XOR destination ranges and the AVX2 absorb length narrow; the bit-string byte
  range widens to 65,535 and its bounded bit-count arithmetic is reviewed.
  The public worker input limit remains 1,024 bytes.
- Constructors/customization: actual `TupleHash` domain bytes and 72-bit name,
  rate selection, checked prefix arithmetic and exact remaining/pending/emitted
  completion. Setup owners are cleared before replacement; compiler-generated
  aggregate moves are separately assigned to enclosing-window reclamation.
- Retained rehash/export: old output survives customization, is absorbed with
  its exact encoded bit length, then cleared. Export checks identity, width and
  final-bit count, checks the callback result and (on AVX2) revalidates authority
  after copying. More-output export returns to Reader; terminal export clears
  the owner and returns to Empty.
- Reader/error/retirement cleanup: scalar 1,024-byte staging and 168-byte partial
  staging, accelerated reproduced scratch cleanup, all nine operation-error
  clear blocks, typed active-state destruction, worker-buffer cleanup and full
  4,096-byte resident-page retirement. Error-block enumeration starts at the
  reviewed cleanup blocks; it is not a general proof of arbitrary control flow.
- Every emitted function and frame has an explicit review/storage assignment.
  Saved incoming vectors, compiler spills and aggregate copies are **not**
  claimed individually erased. Their final whole-window obligation remains
  assigned to step 8, with actual runtime callees named in each report.

The scalar image contains a fail-stop panic path ending at `PublicProbeAbort`.
It is retained in the inventory and frame graph, not treated as a normal
cleanup return. The increment follows `index != slice.len()` in a typed private
slice iteration; valid Rust slice lengths are bounded by `isize::MAX`, and
public input is additionally limited to 1,024 bytes. Thus the increment cannot
overflow on a valid caller path. All three fail-stop wrappers retain their
`call`/`ud2` endings; no cleanup-after-abort claim is made.

## Tests and retained evidence

Fourteen review tests pass on both Linux and Windows with identical parsed reports.
They reject removal of 148 scalar and 124 AVX2 semantic landmarks, 52 actual
cleanup events, 34 domain/phase/rate mutations, twelve private ABI changes,
missing/extra funclets, changed helper contracts, incomplete inventories and
altered body/reference bindings. Byte mutations establish binding durability,
not algorithm correctness or complete erasure by themselves.

The Linux component campaigns also pass:

- Scalar: eight component tests, 272 independent bit cases through direct/wire
  paths, 128 retained rehash cases and 23 compiled mutants. One placement test
  rejects two allocation-clear/lifetime mutants.
- AVX2: nine component tests, 272 independent cases, 128 retained rehashes,
  22 compiled mutants and six ownership negatives.
- Resident/wire: five tests, 29 compiled mutants and seven ownership negatives.
- Worker: one test, nine compiled Rust mutants and eighteen baseline C-gate
  mutants.
- Shipping host/worker metadata parity: one test and ten compiled mutants.
- Focused Miri: two actual packer memory-model tests and three mutants; one
  placement model and three mutants. The noncryptographic doubles do not
  establish kernel or enclave execution under Miri. The first packer attempt
  stopped at cache permissions before testing; the permitted retry passed.
- All nineteen existing KMAC review tests pass after parameterizing the shared
  build-manifest, runtime-name and transport-prefix helpers. Defaults and KMAC
  checks are unchanged.

Inputs are retained locally under `release-reports/windows-local-20261004/`.
Reports, logs and persistent test fixtures are under
`release-reports/windows-worker-review-20261006/`, outside `target/`.
The historical [checkpoint observation](../assurance/windows-protection-observations/tuple-chain-progress-20261006.json)
retains its earlier incomplete scope. The
[composition observation](../assurance/windows-protection-observations/tuple-chain-completion-20261006.json)
records the final private-chain reports and unchanged component receipts.

```sh
python3 scripts/cryptography/test-windows-enclave-tuple-chains.py \
  --saved-directory release-reports/windows-local-20261004
python3 scripts/cryptography/windows_enclave_tuple_chains.py \
  release-reports/windows-local-20261004 --mutate \
  --output release-reports/windows-worker-review-20261006/tuple-chains-composition-linux.json
```

Without saved artifacts the test command runs seven self-contained tests and
explicitly skips the saved-artifact class (seven additional tests). It must not
claim those tests ran when the inputs are absent.

## Remaining shared work

No private TupleHash family-review item remains unassigned. The source/lifecycle
review, actual component/oracle/mutation campaigns and emitted-path composition
are complementary; an inventory/hash match alone is not the closure criterion.

Shared memory/runtime, SDK transport, final platform/depth reconciliation and
full enclosing-window reclamation remain assigned to step 8. Compiler-created
copies, spills and incoming register saves require that window reclamation;
they are not silently considered individually erased. Native development
evidence is not consumer production-signing qualification.
