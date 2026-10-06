# Windows KMAC inner-chain review

The **private KMAC review package is complete** for the two saved images.
This is an author review, not whole-image qualification, independent retest
or a new release gate. Shared runtime and stack-window work remains open.
It covers the saved scalar and AVX2 images from the local Windows development
campaign. Neither a function hash nor a successful component test establishes
whole-image cleanup by itself.

## Reproduced checks

The [reviewer](../scripts/cryptography/windows_enclave_kmac_chains.py) binds the
complete emitted function inventory to the actual linked image, including
relocation destinations, cleanup-funclet metadata, immutable constants, resident
pointer metadata and all indirect-dispatch tables. It validates the saved
assembly, IR, object, image and build manifest, and checks every saved build-input
hash against the current checkout before inspection.

| Saved route | Functions | Build inputs | Local stack bound | Mutation checks |
|---|---:|---:|---|---|
| Scalar KMAC | 84 | 207 | `H-21696` | 40,909 code bytes; 176 table bytes |
| AVX2 KMAC | 64 main + 13 cleanup funclets | 305 | `H-11230` | 27,572 code bytes; 64 table bytes |

All scalar functions are normally reachable. The accelerated route reaches
62 functions normally; two additional drop-glue bodies and the thirteen
cleanup funclets are accounted for through the actual unwind metadata.
This accounting is **not** a claim that arbitrary Windows exceptions execute
every destructor.

`H` is the enclosing 64-KiB window's high address. Bounds conservatively count
tail calls as nested calls, include constant stack probes and alignment slack,
and deliberately exclude shared runtime frames. They are not maximum
whole-image stack-depth bounds. Compiler-created state copies and incoming
nonvolatile register saves still require enclosing-window reclamation; they
are not claimed to be individually erased.

The following semantic checks are additional to identity binding:

- Both complete opaque Keccak schedules, working-register erasure and their
  actual linked round constants. Constants are independently regenerated with
  the Keccak LFSR. The scalar block has no stack access; the AVX2 block clears
  its 576-byte scratch and working vectors before restoring incoming ABI saves.
- Fixed-width tag comparison visits all declared bytes without an early
  mismatch exit. The difference accumulator is cleared. This is not a
  whole-program timing guarantee.
- Right-encoded KMAC suffixes, declared fixed-output lengths versus zero for
  XOF, minimum 128/256-bit fixed-output strengths, exact key-completion
  remaining/emitted counters, and partial-key pending-byte cleanup.
- Finite normal-control-flow checks require the suffix packer's pending byte,
  used byte and count cleanup before return. Both scalar setup completions and
  fixed finalizers have their required cleanup checked on every normal return.
- After worker buffers are constructed, every normal return passes their
  destructor: a 96-byte scalar or 112-byte AVX2 header plus 1,024-byte payload.
  Selected public-export shape, result handling and output-clearing paths are
  checked; AVX2 post-copy authority revalidation is included.
- Private compiler ABI assumptions bind the 1,024-byte update limit,
  owner alignment and extent, final-tail range, and accelerated session/key
  pointer extents. These are typed internal calls, not independently callable
  foreign interfaces with arbitrary pointers.
- The C wrapper's actual worker target and the four `PublicKmac*` transport
  targets are rebound in each KMAC image using the existing wrapper and
  transport reviewers.
- Reuse of prior SHA-3 helpers replays those reviews and compares complete
  bodies, references, extent kinds and resolved LLVM ABI attributes. Twenty-two
  scalar and twenty AVX2 helpers match exactly. Two scalar and four AVX2 renamed
  helpers have explicit role/layout bindings; names are not generally ignored.
  Six scalar and one AVX2 prefix specializations permit only the enumerated
  left-encoding selector, preserved-register initialization and wipe-callee
  substitutions. Every other instruction difference is rejected.
- The generic public-integer encoder is checked separately for left/right
  encoding and full 256-byte initialization. The two AVX2 bit-XOR helpers'
  wider inferred ranges are not silently inherited: count is bounded by eight,
  zero count skips the leaf, both offsets are bounded by `8-count`, and the
  leaf performs exactly one source-byte load and destination-byte XOR.
- Retained-key setup preserves the old output during customization, consumes
  its exact bit shape, and clears it only after successful key setup. Failure
  and cancellation coverage remains supplied by the component campaigns.
- The distinct scalar KMAC constructors bind positive rates 168/136 and a
  32-bit function name, prefix carry arithmetic, pending-byte clearing and
  failure wipes. Successful construction copies 1,040 bytes out of its frame;
  this moved-from stack copy is assigned to enclosing-window reclamation,
  not claimed individually erased. Reader transfer first vacates the source,
  copies its owner, then clears the source before publishing the reader.
- All thirteen AVX2 cleanup funclets reload their expected parent-state
  pointers and call the corresponding operation/state destructor on every
  normal return. The state guard clears its pending key byte. This proves
  what an invoked funclet does, not that arbitrary exceptions invoke it.
- Owner admission checks phase and nonwrapping sequence before use; accelerated
  admission also checks authority health and kernel identity. Setup, key,
  update, finish and squeeze error blocks clear active state and retained output.
  Successful cancellation returns to empty; failed operations quarantine.
  Streaming, squeezing and retained-final/more transitions are bound to the
  actual emitted state writes, with component rejection/unwind tests alongside.
- Scalar fixed/squeeze and accelerated squeeze staging clear their 1,024-byte
  buffers before the reviewed staging exits. The distinct scalar terminal
  readers consume the reader before output, check output counts and clear
  their partial-byte staging. Every normal terminal exit tail-calls the full
  owner wipe. Strength-specific wrappers differ only by explicitly compared
  callee substitutions; a 1,041-byte moved reader remains accounted for in
  the enclosing stack window, not silently treated as individually erased.
- Resident retirement destroys active objects, invalidates the live identity
  and clears all 4,096 bytes with volatile stores. Active-state destruction
  alone is **not** full allocation erasure: inactive enum bytes and padding
  stay inside the resident allocation until retirement. Their protection while
  live depends on the shared page-admission contract.

## Finite review and storage assignments

All 84 scalar and 77 AVX2 bodies have explicit review assignments; unknown or
ambiguous roles fail reconciliation. Thirty scalar and twenty-seven AVX2
assignments reproduce prior helper reviews, including the enumerated ABI and
prefix differences. The remaining assignments cover the entry/wire decoder,
owner lifecycle, setup/framing, readers, state/guard destruction, comparison,
resident lifetime and invoked funclets. Assignment labels record author review;
they are not a substitute for the frozen source/image binding, semantic checks
or compiled component campaigns.

| Storage | Lifecycle accounted for | Shared completion obligation |
|---|---|---|
| Resident owner, authority and retained output | Active-state cleanup; complete volatile page retirement, including padding | Page admission and release |
| Owned input/header and output staging | Bounded copies; buffer destructors and staging cleanup | SDK transport and full window reclamation |
| Compiler aggregate moves, spills and incoming register saves | Every emitted private frame and inner edge recorded; no individual-erasure claim | Complete window erasure and full runtime depth |
| Host input and explicit exported output | Outside protected ownership; export is intentional | No protection claim for caller buffers |

The only mutable globals in these bound paths hold resident pointer identity,
not payload storage. Actual external callees are enumerated; no allocator is
silently admitted. AVX2 `memcmp` is used only by the public startup KAT, not tag
verification. Each runtime edge retains its exact image address and caller list.

## Tests and reproducibility

Nineteen review tests pass on Linux and Windows with identical parsed reports.
On the actual saved assemblies, deleting 110 scalar and 82 AVX2 semantic
landmarks is rejected; removing six scalar and eleven AVX2 private-ABI
assumptions plus two scalar constructor/reader assumptions is also rejected.
The tests additionally reject 24 renamed-helper body/reference/kind/ABI
mutations, 136 prefix-specialization instruction/ABI mutations and 37 actual
lifecycle cleanup-event mutations. Byte
mutations exercise evidence binding, not correctness of the cryptographic
algorithm. These are bounded author-review checks, not a general proof that
arbitrary assembly implements the source semantics.

The accompanying component campaigns pass:

- Scalar: thirteen tests, 256 independent bit cases through direct/wire paths,
  256 retained-rekey cases, 26 compiled mutants and a placement test.
- AVX2 component: sixteen tests, 256 independent cases, 128 retained rekeys,
  22 compiled mutants and six ownership negatives.
- AVX2 worker: nine compiled Rust mutants and eighteen baseline C-gate mutants.
- Resident/wire: seven tests, 29 compiled mutants and seven ownership negatives.
- Shipping host encoder/worker parity: one test and ten compiled mutants.
- Focused Miri: one strict-provenance placement model with three rejected
  mutants, plus two actual key-prefix memory-model tests. Their noncryptographic
  state doubles do not establish AVX2 or enclave execution under Miri.

The scalar and AVX2 component campaigns were rerun for this lifecycle
composition. The earlier worker, resident, host-wire and focused Miri results
are retained for their unchanged inputs; they were not rerun or relabelled as
new native enclave executions by this follow-up.

Persistent reports and fixture builds are kept locally beneath
`release-reports/windows-worker-review-20261006/`, outside `target/`.
The input images remain in `release-reports/windows-local-20261004/`.
The initial [observation](../assurance/windows-protection-observations/kmac-chain-progress-20261006.json)
is preserved. The follow-up [composition observation](../assurance/windows-protection-observations/kmac-chain-composition-20261006.json)
records its then-incomplete scope. The final
[private-chain observation](../assurance/windows-protection-observations/kmac-chain-complete-20261006.json)
records this composition and its explicit shared obligations.

```sh
python3 scripts/cryptography/test-windows-enclave-kmac-chains.py \
  --saved-directory release-reports/windows-local-20261004
python3 scripts/cryptography/windows_enclave_kmac_chains.py \
  release-reports/windows-local-20261004 --mutate \
  --output release-reports/windows-worker-review-20261006/kmac-chains-lifecycle-linux.json
```

Without `--saved-directory`, the test command runs fifteen self-contained tests
and explicitly skips four saved-artifact tests. It must not report those
campaigns as executed when the local artifacts are unavailable.

## Remaining shared work

Commit-plan step 3 is closed for the frozen private KMAC populations. Shared
`memcpy`, `memset`, `memcmp` where present, `__chkstk`, `__umodti3`, SDK transport,
and final enclosing-window/compiler/platform reconciliation remain assigned to
the existing shared-runtime package (step 8). Full window cleanup, including
moved-from copies, remains a real obligation before whole-image qualification,
not a waived limitation. No release policy or production source
was changed by this review.
