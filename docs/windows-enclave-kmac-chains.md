# Windows KMAC inner-chain review

This is an **in-progress author review**, not completion of the Windows KMAC
package, native qualification, independent retest or a new release gate.
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

## Tests and reproducibility

Fourteen review tests pass on Linux and Windows with identical parsed reports.
On the actual saved assemblies, deleting 66 scalar and 64 AVX2 semantic
landmarks is rejected; removing six scalar and eleven AVX2 private-ABI
assumptions plus two scalar constructor/reader assumptions is also rejected.
The tests additionally reject 24 renamed-helper body/reference/kind/ABI
mutations and 136 prefix-specialization instruction/ABI mutations. Byte
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

Persistent reports and fixture builds are kept locally beneath
`release-reports/windows-worker-review-20261006/`, outside `target/`.
The input images remain in `release-reports/windows-local-20261004/`.
The initial [observation](../assurance/windows-protection-observations/kmac-chain-progress-20261006.json)
is preserved. The follow-up [composition observation](../assurance/windows-protection-observations/kmac-chain-composition-20261006.json)
records the expanded checks, report identities and still-incomplete scope.

```sh
python3 scripts/cryptography/test-windows-enclave-kmac-chains.py \
  --saved-directory release-reports/windows-local-20261004
python3 scripts/cryptography/windows_enclave_kmac_chains.py \
  release-reports/windows-local-20261004 --mutate \
  --output release-reports/windows-worker-review-20261006/kmac-chains-composition-linux.json
```

Without `--saved-directory`, the test command runs eleven self-contained tests
and explicitly skips three saved-artifact tests. It must not report those
campaigns as executed when the local artifacts are unavailable.

## Remaining package work

Commit-plan step 3 remains open. The remaining work is to finish the complete
owner/state lifecycle composition across both routes and account for all
temporary-copy lifetimes against the enclosing-window obligations. The helper
reuse, enumerated prefix specializations, widened XOR, retained-key ordering,
constructor/reader checks and invoked-funclet checks above are no longer
unreviewed items; they must be included in that final composition.

Only after that composition can the private KMAC package be closed. Shared
`memcpy`, `memset`, `memcmp` where present, `__chkstk`, `__umodti3`, SDK transport,
and final enclosing-window/compiler/platform reconciliation remain assigned to
the existing shared-runtime package. No release policy or production source
was changed by this review.
