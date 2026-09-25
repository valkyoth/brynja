# v0.24.49 register-cleanup qualification status

Updated 2026-09-25. This is a work checklist, **not a new release gate**.
The [pentest ledger](../../security/pentest/v0.24.49.md) retains the historical
checks and their limitations. Earlier checkpoint paragraphs are not a current
todo list: several were superseded by later implementation and tests.

Retained KMAC inspections use the local source-matching checkout based on `cc5b9add`
under `dist/register-cleanup-review-source`; see the diagnostic README for the
command. A later Arm CI test correction changes a captured test-file hash, not
production behavior. Exact source/artifact validation remains enabled; the old
record must not be presented as validating the corrected main checkout.
Later diagnostic-only additions can run there without replacing captured sources.

## Already implemented

- All sixteen existing accelerated kernel entries have opaque computation and
  working-register cleanup implementations. The baseline x86-64/AArch64 scalar
  SHA-2, Keccak, SHA-1 and MD5 ports and shared borrowed secret operations exist.
- Scoped caller-owned APIs exist for the hash families, KMAC, TupleHash,
  ParallelHash and applicable accelerated/batch/threaded paths. Their framing,
  buffering and output-transfer remediations and lifecycle regressions are
  recorded in the ledger. These are not still awaiting initial implementation.
- KMAC comparison differences remain in owned memory; only the authentication
  decision is exposed. Its long focused Miri test passed historically. Loss of
  that log to Cargo clean is recorded, not represented as retained evidence.
- The retained optimized portable KMAC bulk/final reader chain now composes
  metadata, ownership, error/unwind, counter, staging, mask and cleanup checks.
  The current [KMAC diagnostic record](kmac-verify/README.md) lives under ignored
  `dist/`, outside Cargo's `target/` directory.
- Accelerated KMAC bulk/final entry forwarding and consuming reader cleanup now
  bind to the actual same-row producer, destructor, engine-memory wipe and core
  clearing functions. The producer entry also binds complete destination
  initialization before state/authority work, the full ownership-descriptor
  transfer, and initialization-failure cleanup. Completion now binds original
  output ownership, failed-finish clearing and recoverable-unwind cleanup to the
  actual core finish and operation guard. Producer valid-bit/state/authority
  admission, bounded loop progress, final-byte masking and owned writes now
  compose with those boundaries and the actual helper checks. These retained
  optimized checks do not qualify debug call chains or whole-call spills.
- Debug KMAC bulk-reader bridges now bind to the actual same-configuration
  SHA-3 wrappers and error-conversion helpers. Their descriptor-only handoff
  preserves the borrowed owner, destination, length, success ownership and exact
  errors; a synthetic producer unwind propagates without publishing a result.
  The debug producer body remains an explicit unchecked boundary in this check,
  not an inferred cleanup guarantee.
- Accelerated debug consuming-final bridges now bind fourteen-function
  handoff/destructor/core-clear closures. Normal success, each backend error and
  synthetic producer unwind request complete same-owner engine/staging/domain
  clearing before publishing the exact result or resuming the original
  exception. Producer and volatile primitive bodies remain explicit boundaries
  of this check; the existing volatile-helper checks retain their own scope.
  Whole debug verifier paths remain outstanding.
- The portable debug final-output constructor now binds its nineteen-function
  shape/checked-length closure, including the actual separately emitted
  `brynja-hash-core` range helper. All 256 final-bit values are modeled across ten
  selected length boundaries in all eight debug configurations. The eight extra
  helper files were verified against the protected original archive and pinned
  separately; they were not silently added to the original runtime record.
  Constructor qualification does not establish the consuming caller's handoff,
  producer cleanup or whole-call register/spill behavior.
- Portable debug consuming-final bridges now compose the actual constructor,
  reader handoff, descriptor extraction, destructor chain and error conversion
  in thirty-five-function closures. Both reader strengths preserve the original
  owner/active flag/output shape, request all thirteen owned-region clears once
  on ordinary return and selected boundary unwind, and preserve exact results.
  Shape rejection clears before returning; successful transfer clears before
  publishing the producer result. Producer and volatile primitive bodies remain
  opaque here, and arbitrary helper/double-panic unwind is not qualified.
- Portable debug producer handoff and operation guards now bind nineteen-function
  closures. The initializer call precedes terminal-state handling; its
  complete descriptor and output-shape captures reach the operation. Initialization
  failure deactivates/clears the owner; terminal rejection drops the initializer;
  only operation success restores active state. Errors and selected boundary
  unwind execute the actual guard/destructor chain and owned-clear requests.
  Initializer, squeeze/finish-operation and volatile primitive bodies are explicit
  boundaries, not behavior inferred from the guard model.
- The debug destination-initializer body now binds its core constructor, slice
  helpers, full-region clear request, ownership construction and error conversion.
  Its twelve/thirteen-function closure is also composed with the portable producer
  guard in twenty-nine/thirty-function closures. Empty output produces no owner;
  nonempty output requests its complete clear before returning the original
  destination with zero initialization progress. The core constructor preserves
  exact errors before the SHA-3 adapter deliberately maps them to `SecretMemory`.
  This supersedes the opaque initializer boundary for those composed paths;
  squeeze/finish-operation and volatile primitive bodies retain their own scope.
- The debug SHA-3 output-completion adapter now composes its actual sixteen-
  function ownership/result-conversion closure with core initialization finish
  and Drop. Completion transfers the original descriptor; incomplete/missing
  owners return `SecretMemory`, requesting complete clearing when an owner exists.
  Selected helper unwind preserves exception identity and clears the owned output.
  All adapter/core blocks except unreachable and cleanup double panic are covered.
  This checks the completion helper, not its upstream squeeze/operation caller.
- Portable debug producer operations now connect the actual initializer, guard,
  dispatch closure and completion/destructor chain in forty-five/forty-six-
  function closures. Original owner, initializer, length and optional bit shape
  reach the selected squeeze boundary; empty output takes the zero-increment
  limit check. Synthetic partial progress, errors and selected unwind exercise
  destination cleanup, owner cleanup and success-only reader reactivation.
  Actual squeeze/check and volatile bodies remain explicit boundaries. All
  operation-closure blocks except unreachable/cleanup double panic are covered;
  standalone helper checks retain their separately documented coverage.
- The debug output-limit helper now binds its six-function checked-u128-addition,
  counter-field selection and result-mapping closure, composed with the portable
  empty-output producer in fifty-one/fifty-two-function closures. Exact sums and
  overflow tags are checked independently of the adapter that discards the sum.
  Zero-length output succeeds even at the maximum counter; terminal readers
  cannot read the counter, and synthetic decoder unwind follows owner cleanup.
  The counter decoder and volatile primitive remain explicit boundaries; this
  does not establish scalar-counter register/spill cleanup or squeezing behavior.
- The debug counter decoder now includes its actual twelve-function iterator,
  conversion and shift closure, composed with output-limit and empty-producer
  paths in sixty-three/sixty-four-function closures. It reads exactly the sixteen
  original counter bytes once, in order, and reconstructs the little-endian u128.
  Checked offset conversion/multiplication defaults are separately exercised;
  normal helper blocks are covered without entering the two panic boundaries.
  Rust 1.98's packed result ABI preserves undefined padding in the model. This
  closes the opaque decoder boundary for these paths, not scalar temporary
  erasure, actual squeezing or whole-verifier register/spill qualification.
- The actual byte-squeeze callee now binds a fourteen-function counter-writer
  closure, including mutable iteration, byte narrowing and defaults. The combined
  writer/decoder/helper set contains seventy-two/seventy-three functions. Every
  byte starts incorrect, is written exactly once in order, and round-trips through
  the actual decoder. Narrowing is checked for every byte value and selected
  overflow values. This checks the helper's modeled effects, not the squeeze
  caller's execution or counter-commit ordering, nor scalar/register/spill erasure.
- The portable debug byte-squeeze body now composes its actual counter decoder/
  writer, checked arithmetic, staging-slice and output-initialization write
  helpers. Its fifty-eight-function closure joins the earlier helpers in
  ninety-eight/ninety-nine-function sets. Modeled iteration failures check exact
  prefix progress, full staging-clear requests after returned write attempts,
  and counter commit only after every chunk succeeds. Staging fill, byte copy
  and volatile wiping remain explicit boundaries. Selected boundary unwinds
  propagate without a counter commit; the enclosing guard's cleanup must still
  be composed with this body. Final-bit squeezing and whole-call residue remain
  unqualified; this is not a register/spill-erasure guarantee.
- Portable debug byte squeezing now executes inside the actual producer,
  initializer, operation, completion and guard/destructor chain. The composed
  check binds exact output progress and success-only counter commits to complete
  destination/owner clear requests on returned failures and selected fill/copy
  unwind. It also checks initializer failure, terminal-state rejection and empty
  output. Fill/copy/volatile primitives remain explicit boundaries. This closes
  the previously separate byte-squeeze/outer-guard link for the modeled cases,
  not final-bit paths, arbitrary unwind or register/spill erasure.
- The portable debug final-bit squeeze helper now composes nineteen additional
  same-configuration helpers with the earlier byte-squeeze/counter/write model.
  All 3,888 selected cases pass across sixteen instantiated paths. Exact prefix
  length, checked bit admission, partial-byte mask requests, output progress and
  staging-clear ordering are checked. The byte counter commits after the complete
  prefix, before the tail: a tail failure does not undo that commit inside this
  helper. That direct check does not compose the outer guard (covered below);
  its result must not be represented as whole-call cleanup. Fill/copy/mask/volatile
  primitive bodies remain opaque, and this is not register/spill qualification.
- Portable debug final-bit squeezing now runs inside the actual producer,
  initializer, operation, completion and guard/destructor chain. All 5,984
  selected cases pass, including tail failures after the prefix counter commits.
  Failures after processing starts and selected fill/copy unwind request complete
  output and thirteen-region owner clearing, with exact prefix accounting and
  original exception propagation. Only successful producer completion restores
  the borrowed reader's active flag; this is not public final-API reuse. This
  closes the direct final-bit helper/producer-guard link for the modeled cases.
  Already-terminal rejection requests output clearing without another owner mutation.
  The consuming-reader wrapper is still separately checked, not composed here;
  secret primitives and whole-call register/spill behavior remain unqualified.
- The subsequent consuming-final diagnostic connects that producer to the
  actual output constructor, SHA-3 consuming reader and KMAC trait bridge.
  All 6,272 modeled cases pass through the combined 149/150-function closures.
  The original compiler-local reader/result descriptors, exact output progress,
  counter effects and exception identity survive the handoff. Consuming cleanup
  requests all thirteen owner-region clears before return or resumed unwind,
  including after an inner guard already requested clearing. Constructor shape
  rejection consumes the owner without promising destination erasure. All 192
  injected regressions reject and sixteen SSA controls pass. This does not qualify
  secret primitive bodies or whole-call register/spill cleanup.

- Portable debug bulk-reader forwarding now composes the actual guarded byte
  producer in 103/104-function closures. All 7,936 modeled cases pass across
  sixteen paths, preserving original borrowed reader/output addresses, exact
  counter/progress effects, success-only reuse and error/unwind cleanup ordering.
  All 256 outer handoff/result/payload-access mutations reject, with sixteen
  passing SSA rename controls. The independent producer oracle is checked before
  comparing the composed trace. Fill/copy/volatile bodies remain opaque; this
  completes the portable bulk-reader/producer link, not whole-call erasure.

- The portable debug staging-fill body now includes its actual 32-function
  range/cursor, checked-arithmetic, slice, core-copy-wrapper and scratch-clearing
  helper closure. All 43,136 geometry/error cases pass across sixteen paths;
  all 320 mutations reject with sixteen passing SSA controls. The scalar handoff
  binds four original state/scratch borrows and the exact immutable round table.
  Failed copies cannot advance that chunk's cursor. Selected primitive unwind
  propagates without inventing cleanup absent from this standalone helper.
  Scalar/copy/volatile bodies remain opaque and the outer squeeze/guard link
  must still be composed with this fill body; no whole-call erasure is claimed.

- The debug staging-fill body now executes inside the actual byte squeeze,
  initializer/completion and owner-guard chain in 118/119-function closures.
  All 3,760 cases pass across sixteen paths, with 336 rejected mutations and
  sixteen passing SSA controls. Staging cursor/copy progress, full output/owner
  clearing requests on failures and selected synthetic primitive unwind, and
  success-only output-counter commit/reader reuse are checked together. This
  closes the byte-squeeze/staging-fill link. Final-bit caller composition and
  whole-verifier coverage remain outstanding; primitive bodies stay opaque.

- The same staging-fill body now composes with the guarded debug final-bit
  squeeze in 137/138-function closures: all 17,680 cases pass, all 464 mutations
  reject and sixteen SSA controls pass. The matrix checks prefix/tail cursor
  progress, exact masks, prefix-counter commit even before a later tail failure,
  and output/owner cleanup requests with success-only reader reactivation.
  These remain portable-reader paths in portable/accelerated builds. The
  consuming wrapper is not yet composed with this filled chain; primitive
  bodies, accelerated guards and whole-verifier qualification remain separate.

- The consuming wrapper now includes the actual staging-filled final-bit chain
  in 167/168-function closures. All 17,968 cases pass, all 656 mutations reject
  and sixteen SSA controls pass. Constructor rejection/unwind, original local
  reader binding, prefix/tail effects, error translation and final owner cleanup
  are checked together against an independent lifecycle envelope, not a second
  execution of the producer as its own oracle. This closes the consuming/filled
  portable-reader link for the modeled cases. Primitive bodies, accelerated
  reader guards and whole-verifier/register/spill coverage remain separate.

- Accelerated debug producer/local-guard coverage now checks 22-function
  closures across eight compiler/target/identity paths. All 10,752 cases pass;
  760 mutations reject and sixteen metadata/SSA controls pass. Original output,
  initializer and storage borrows are preserved. Success clears staging and
  disarms the guard; rejection and selected synthetic unwind request terminal
  owner cleanup. Initializer/operation/volatile bodies remain opaque, so their
  composition with these guards and the reader bridges is still outstanding.

- Accelerated debug initialization, operation chunk dispatch, output writes and
  completion now compose with the actual local guard in 79/80-function closures.
  All 31,296 cases pass across eight paths; 1,034 mutations reject with twenty-four
  positive controls. Failed operations clear their original destination before
  the guard requests owner cleanup; success transfers output ownership and
  clears staging. All nonpanic operation blocks are exercised. Engine preflight,
  engine read, copy, mask and volatile bodies remain opaque. Outer reader bridges
  and engine-body composition still need review; this is not whole-call erasure.

- Both accelerated debug reader bridges now compose with the actual initializer,
  operation loop, completion and guard: 28,264 cases pass across eight paths,
  in 84/85-function bulk and 87/88-function consuming closures. All 1,012 outer
  mutations reject with thirty-two positive controls. Original reader/result
  descriptors remain bound; consuming calls request owner cleanup even after
  producer success, while bulk calls preserve the producer's reusable-reader
  outcome. Engine preflight/read and primitive bodies remain opaque; whole-
  verifier and whole-call register/spill qualification are still outstanding.

- Accelerated debug preflight now executes its actual nineteen-function
  terminal-state, session-result, counter-decoding and checked-addition closure,
  both directly and beneath the bulk/consuming reader bridges. All 19,808 cases
  pass, including 8,784 composed reader cases. Counter bytes are read exactly
  once in order after state/authority admission; overflow and exact backend
  errors propagate through output/owner cleanup. All normal preflight/helper
  blocks are covered except forbidden panic paths. Session-check internals,
  engine read and copy/mask/volatile bodies remain opaque. Scalar counter
  temporaries, register/spill cleanup and whole-verifier coverage remain
  unqualified; this is not F1 closure. All 1,248 mutations reject with eighty
  metadata/SSA/no-op controls; 2,744 existing bridge cases also still pass.

- The accelerated debug engine-read body now executes its actual preflight,
  counter decoder/writer, permutation adapter and inner cleanup guard. All
  4,624 cases pass across eight retained paths; 1,534 mutations reject with forty
  positive controls and complete nonpanic read-body block coverage.
  Checked cursor/rate bounds, exact lane/output copy slices,
  success-only full counter commits and terminal owner-clear requests on errors
  and selected unwind are checked independently. CPU session/permutation,
  slice-splitting, copy and volatile primitives remain explicit boundaries;
  this direct check does not yet compose the read body with the outer producer
  and reader guards. It does not qualify output bytes or register/spill cleanup.

- The accelerated debug engine-read closure now executes beneath both actual
  bulk and consuming readers in one metadata model with original storage shared
  across all chunk calls. All 8,576 cases pass across eight retained paths,
  including later-chunk failures and inner-to-outer cleanup/exception flow.
  All 224 focused IR mutations reject with thirty-two controls; twenty-six
  malformed model-boundary cases reject. This closes the previously opaque
  engine-read handoff, not the still-opaque session/permutation/split/copy/mask/
  volatile primitive bodies. Whole-verifier and register/spill qualification
  remain open; no production implementation or release-gate policy changed.

- The retained split/copy/mask wrapper bodies now execute directly and beneath
  both accelerated debug readers. The eight-path matrix covers 4,896 direct
  primitive cases and 8,576 composed cases, with 352 rejected IR mutation
  executions and thirty-two controls. Actual split descriptors and exact raw
  copy/mask arguments are checked, not supplied as expected results. Four
  same-row x86/Arm copy/mask assembly pairs pass exact normal-return instruction
  contracts, rejecting 116 mutations with eight label controls. Valid borrowed
  pointer preconditions remain assumptions; CPU session/permutation and volatile
  bodies, wrapper/whole-caller spills and whole-verifier qualification remain
  outstanding. These checks do not close F1 or change release gates.

Implementation completion is not qualification completion. Marker-free return
observations alone do not prove absence of transformed secrets or stack spills.

The retained six-function volatile-clear closure now executes beneath the actual
accelerated readers, including inner engine, staging, output and consuming-owner
cleanup. All 288 focused cases pass across eight paths, completing 3,064 clearing
calls. Exact byte order, zero values and the final SeqCst compiler fence are
checked against the original caller regions. All 192 IR mutations reject with
sixteen controls; fifteen malformed boundary cases reject per shard. Valid
byte-pointer precondition return remains an assumption. This composes the
previously opaque volatile body but does not qualify whole-call spills or close F1.

The static Keccak session now has a retained 26-function metadata check: 800
cases pass across four compiler/architecture builds. It executes actual health,
generation and compiled-feature admission, exact kernel selection, operation
guard completion, seven scratch-clearing requests and terminal quarantine.
All 458 mutations reject with eighteen semantic/metadata controls. That standalone
coverage binds the SHA-3 imported identities; the reader composition described
below builds on it. Kernel payload qualification remains separate. The retained
fixture does not enable the hosted runtime route. F1 remains open.

The follow-up reader/session composition now executes those actual static CPU
guards beneath the bulk and consuming-final readers, on their original borrowed
storage. Its 168 focused cases span all eight retained paths, checking 656 CPU
calls and 3,680 actual volatile clears. Admission rejection prevents dispatch;
kernel error/synthetic unwind wipes scratch before quarantine and propagates
through engine/output cleanup. All 72 integration IR mutants reject with sixteen
SSA/metadata controls; twelve alias/payload/frame boundary tests reject per shard.
Raw kernel payload computation remains opaque, with its separate evidence reused.
This closes that composition gap, not whole-verifier/caller spill qualification.
The diagnostic record distinguishes this focused matrix from the earlier broader
standalone session and reader matrices. No production or release policy changed.

The debug verifier's post-`finish()` ownership handoff now replays its actual
result-branch helper, discriminator, reader-field transfer and cleanup-guard
initialization. All 864 descriptor cases pass across 24 verifier instances;
408 IR mutations reject with 48 metadata/block-label controls. The returned
metadata owner reaches the actual three-region guard cleanup, the live-reader
flag is armed only on success, and the exact error byte reaches the residual
conversion boundary without creating either owner. This is a bounded fragment:
`finish()` results are contract inputs, synthetic fragment stops are not verifier
exits, and later comparison/cleanup control flow is not executed by this replay.
Ten direct boundary tests reject payload access and malformed transfers. It
extends the earlier CFG invocation check with returned-descriptor provenance,
not a whole-verifier or register/spill qualification claim.

The debug bulk-comparison caller now has a bounded retained-IR replay across all
24 verifier instances: 2,480 descriptor/chunk cases and 20,688 ordered byte-pair
handoffs pass. It executes the actual result helper and caller loop, checks the
original candidate-chunk inputs, original verification-buffer bytes and the
one-byte difference accumulator, and rejects reader errors without exposing an
output. All 1,008 caller/helper mutations reject, with 48 label/metadata controls
and eight direct payload/copy-boundary rejections. Reader results, output
exposure, standard-library iterators and the comparison primitive are explicit
contracts, not newly executed helper bodies. Synthetic stops are at the original
output-Drop/residual boundaries; they do not prove those exits or unwind paths.
This is bulk caller routing evidence, not full comparison-chain qualification.

The corresponding final-byte caller fragment now passes 3,392 cases across 24
instances, including 192 exact final-byte handoffs, every applicable reader
error and an unexpected empty-output result. Actual Option/Result helpers
preserve errors and reject missing output before comparison. All 912 selected
caller/helper mutations reject, with 48 label/metadata controls and ten direct
boundary rejections. The byte pointer is traced to the actual `first()` success
field, not merely an equal-valued metadata-owner pointer. Output exposure,
`first()`, iterator and comparison primitive contracts remain explicit; producer
masking, full-chain composition and subsequent cleanup/unwind are not newly
qualified by this bounded replay.

The actual debug `finish()` body now composes with the caller's reader/guard
transfer across 24 instances: 4,368 cases, 1,216 successful transfers and 48
modeled suffix-unwind paths pass. Admission precedence, exact requested bit
length/input-descriptor forwarding, returned reader fields, metadata-owner
identity, error propagation and destructor requests are checked. All 1,392
body/helper mutations reject, with 48 label/metadata controls and twelve direct
boundary rejections. State/key classification, suffix framing/state consumption
and state/Core destructor internals remain explicit contracts. This closes the
previous isolated finish-result input at the handoff, not the entire producing
or cleanup chain; it does not establish physical erasure or real unwind behavior.

The previously opaque Core/Borrowed destructor bodies now have a separate
same-row KMAC/SHA-3 check. All 24 debug instances pass 512 scenarios, including
256 modeled state-destructor entry unwinds and 2,624 exact owned-clear requests.
Present portable state requests thirteen engine regions; accelerated state sets
the two cancellation fields before requesting six regions. Absent state does
not clear an engine. Core destruction requests metadata cleanup after state
cleanup, or before resuming the original modeled exception. All 888 IR mutations
reject with 48 label/metadata controls and eight boundary rejections. These
destructor bodies still need composition with actual suffix state consumption;
the volatile clear body retains its separate evidence. This is not physical
erasure, native unwind or whole-verifier qualification.

## Before the next independent pentest

1. **Finish the remaining instantiated KMAC path review.** Complete debug
   caller/reader coverage beyond bulk and consuming-final bridges, including
   suffix-producer/destructor composition and full comparison-chain composition, whole-verifier error/unwind
   paths, and reconcile the optimized
   caller-to-reader/dependency coverage before
   claiming the whole instantiated path qualified. Individual helper checks are evidence to reuse,
   not a reason to assume an unchecked call-chain link is correct. The optimized
   portable bulk/final chain and accelerated producer admission/loop/completion
   boundaries and the debug reader/static-session/volatile-clear composition
   are no longer the next unfinished items.
2. **Complete the wider caller and worker emitted-code review.** Check the
   remaining scoped SHA-2/SHA-3, legacy, TupleHash and ParallelHash call boundaries
   against their stated contracts, including actual worker handoff/return paths.
   Coordinator observations after joining threads do not establish worker
   register or spill cleanup. Fix any concrete secret-copy/residue path found
   within the intended qualified boundary and add a regression for it.
3. **Reconcile the exact guarantee and coverage.** Keep supported compiler,
   target, ABI, feature and normal-return boundaries explicit. Existing movable
   APIs and other-target portable models must not inherit a stronger guarantee
   merely because a scoped x86/Arm path passes. Preserved caller state, signals,
   abort and platform snapshots remain outside the stated kernel contract.
   Any unresolved in-scope behavior must remain visible to the reviewer.
4. **Finish targeted validation and the review handoff.** Reuse unchanged,
   source-bound results; rerun affected correctness, ownership/error, cleanup,
   sanitizer and performance checks when their inputs actually changed. Refresh
   the existing review bindings/documentation and commit a stable candidate with
   an accurate finding disposition. Do not mark F1 closed on author checks or
   delete root `PENTEST.md` while remediation/retest remains outstanding.

These are qualification work packages, not a claim that each needs a new
implementation or a full verifier sweep. Missing local artifacts must be
reported accurately; recover only the evidence needed for the current review.

## After a clean pentest, before release

- Collect/review fresh source-bound native Linux x86, Linux Arm and macOS
  evidence, plus native Windows ABI/runtime evidence for the Windows claims.
  Cross-compilation and QEMU are not substitutes for those native lanes.
  Dedicated x86 SHA512 is still SDE-only in the observed fleet; label it as
  emulation unless a suitable native host becomes available.
- Run the owner-approved final verification using the existing planner, gates
  and evidence-reuse rules; check GitHub, then request tag/push authorization.
  This checklist changes none of those mechanisms.

F2–F5 have implementation/test changes awaiting independent retest. F1 remains
open for the wider qualification described above; the original sixteen-kernel
rewrite is not missing. No military suitability, independent verification or
FIPS validation is claimed.
