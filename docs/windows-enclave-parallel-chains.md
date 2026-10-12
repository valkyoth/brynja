# Windows ParallelHash family review

Package 7 is **open**. This is a saved-image author review, not a release gate,
new native enclave run, independent retest or whole-image qualification.
Production Rust, signed images and release-gate policy are unchanged.

Latest progress: **all three Rust-family route reviews are conditionally
complete** (regrouped Passes A–B). All 61 scalar, 73 AVX2 and 64 concurrent
bodies, including 17 cleanup funclets, have explicit assignments and
caller/lifetime composition. The combined reconciliation remains open
(pass 4 / regrouped Pass C). Package 8 prerequisites are unchanged.

The earlier progress sections below describe their historical checkpoints;
the route closure sections supersede their earlier remaining-work statements.

## Finite completion plan

1. Bind all three Rust populations, replay earlier primitive and selected
   scheduler reviews, and enumerate every remaining body/path assignment.
2. Complete both sequential routes: root/leaf framing, exact completion,
   customization and rehash, retained output, original allocation lifetimes,
   failure/handler paths and owner/page retirement.
3. Complete the concurrent route: per-thread authority and storage, slot
   publication, generation/receipt ordering, join-before-reuse, canonical CV
   reduction, cancellation and per-window lifetime/retirement.
4. Combine all three route assignments, run the affected regressions on Linux
   and Windows, reconcile evidence and close the conditional family review.

The existing package 8 retains compiler/runtime/SDK, cumulative stack/home-space,
Win64 preservation, complete window reclamation and outer-return qualification.
Family closure must not silently claim those shared obligations are discharged.

## Pass 1: complete populations and explicit reuse

Pass 1 is complete. The [validation record](../assurance/windows-protection-observations/parallel-pass1-20261012.json)
records 114 tests passing with no skips on Linux (14.624 seconds) and Windows
(20.427 seconds). Fresh parsed reports match, all 73 checker-source bindings
match current files, and 77,211 complete-body byte mutations are rejected.
The new tests additionally cover ABI/attribute and linked-constant substitutions.
Local runner setup failures were corrected and excluded from PASS evidence.
Passes 2–4, and therefore package 7, remain open.

| Route | Emitted Rust functions | Cleanup funclets (included) | Exact helper bodies/ABIs | Remaining body assignments |
| --- | ---: | ---: | ---: | ---: |
| Sequential scalar | 61 | 0 | 25 | 36 |
| Sequential AVX2 | 73 | 13 | 21 | 52 |
| Concurrent AVX2 | 64 | 4 | 17 | 47 |

The [frozen population manifest](../assurance/windows-protection-observations/parallel-populations-20261012.json)
binds the exact archive members, complete object bytes, signed images, saved
assembly/LLVM listings and build manifests. All 173 scalar, 269 accelerated and
305 concurrent source inputs must still match. Actual COFF function extents,
relocations, PE destinations and cleanup metadata are checked before reuse.
Every body is reachable from its route's entry or bound handler metadata.
Compiler-builtins and C/SDK objects are not silently included in the Rust-family
population; their outgoing references remain explicit obligations.

The checker reruns the prior KMAC/SHA-3 primitive review before comparing the
current helper's complete bytes, relocations, extent kind and resolved LLVM ABI.
Referenced constant data must also be immutable, relocation-free, rebound to
actual current image bytes and identical to the prior helper's constant data.
It does not trust a historical PASS summary or discard compiler attributes.
There are nine same-body ABI differences (three sequential AVX2, six concurrent);
none is automatically accepted. They remain in the 135 outstanding body
assignments along with 126 distinct bodies.

Even the 63 exact matches establish only a reusable helper-body contract.
Current caller pointers, lifetimes and transitive callee contracts still require
composition. The report separately records these path obligations, so matching
all helper hashes cannot close package 7.

For the concurrent image, the earlier slot, publication, root-setup and
outer-root-return checks are freshly replayed against the same actual Rust and
native objects and signed image. Their selected/partial scope is preserved;
this does not convert old selected review into full scheduler qualification.
The nospill wrapper build is selected, not the older wrapper snapshot.

The saved concurrent assembly calls one `Waves::finish` handler `dtor$54`, while
the actual linked object calls it `dtor$55`. As documented in the earlier
[whole-image review](windows-enclave-whole-image-cleanup.md), the object is
authoritative. Pass 1 binds its actual bytes/metadata and does not use that
assembly listing as a semantic cleanup proof. The remaining concurrent review
must retain this distinction.

## Pass 2: selected sequential leaf paths

Pass 2 is **in progress**, not closed. The
[selected-leaf record](../assurance/windows-protection-observations/parallel-leaf-completion-20261012.json)
records 128 tests passing without skips on Linux and Windows, matching parsed
reports and 77 current checker-source bindings. This includes the preceding
114 tests and 14 additional tests, not a new native enclave capture.

The new checks bind twelve actual emitted bodies across scalar and AVX2:
`Input::absorb`, `Input::finish`, `Input::flush`, `Input::clear`, encoded-integer
destruction, and the two AVX2 leaf cleanup funclets. They check:

- Positive absorption progress, `min(B-used, remaining)`, cursor preservation,
  complete-block flushing and the bounds making the used-counter addition safe.
- Checked total-bit addition, the full 67-bit `B*8` divisor, zero pending bytes
  and exact `ceil(total_bits/(B*8))` leaf count before root suffix absorption.
- The actual optimized right-encoding counter and shifts, including all sixteen
  u128 encoding widths; bounds reject before invalid shifts or stores.
- A 64-byte temporary chaining value (CV), strength-specific 32/64-byte terminal
  output, root absorption before count commitment, and full CV erasure on
  returning paths after CV creation. The bound invoked AVX2 handler clears the
  same parent CV allocation; this does not promise arbitrary-exception cleanup.
- Typed leaf destruction before disarming, three 16-byte counter clears, and
  complete 17+1-byte encoded-integer destruction. The authority borrow survives
  input clearing; inactive enum padding and earlier moved copies remain outer
  allocation/window obligations.

The tests reject 5,046 selected-body byte mutations and independently reject
2,036 instruction-byte mutations without using the whole-body hash check.
They also mutate branch conditions/destinations, relocation targets and
operands, and every byte of the selected complete clearing/handler bodies.
Seeded word-arithmetic and cursor models are compared with mathematical
ceiling and big-endian encoding oracles; these models are not CPU execution.
The external `__udivti3` implementation/ABI remains in package 8.

### Object/listing distinction

Inspection found separate-emission differences in scalar and AVX2
`Owner::finish_custom`, `Input::finish`, and `Owner::finish_root`. Register
allocation and encoding-loop instructions differ, not just label spelling.
Two AVX2 handler names in the listing (`dtor$31`/`dtor$35`) also differ from
actual COFF/xdata names (`dtor$32`/`dtor$36`). No production discrepancy or
algorithm failure is inferred from this: the actual objects still bind to the
saved signed images. But listing text cannot prove those object instructions.
The selected leaf checker therefore uses actual COFF instruction bytes,
relocations, branch destinations and PE/xdata bindings, without relabeling a
separately emitted listing and treating it as equivalent.

These selected checks do not remove the enclosing caller obligations or close
package 7. The root-framing follow-up below advances the same second pass.

## Pass 2 root framing, setup conversion and retained rehash

The [root-framing record](../assurance/windows-protection-observations/parallel-root-framing-20261012.json)
records 141 passing combined tests on both Linux and Windows, with no skips and
matching regenerated reports. It adds twelve actual bodies: `finish_root`,
`finish_custom`, `finish` and `rehash` on each sequential route, plus their four
invoked AVX2 cleanup funclets. All 6,852 bytes of these selected bodies have
named instruction-span contracts; no separately emitted listing substitutes
for the actual object. The prior leaf and complete-population reviews are
replayed, not accepted from an old PASS summary.

The new checks cover:

- Actual read-only allowed-phase data, direct call targets, argument addresses,
  operand addends, full body extents and parent-xdata cleanup destinations.
- Setup completion checks, scalar source erasure and root replacement, and
  AVX2 in-place completion after authority and exact customization checks.
- `left_encode(B)`, widened output-bit arithmetic and `right_encode(L)`, with
  exhaustive output-shape tests and independent integer-encoding oracles.
  Both final-message and rehash callers require zero output width for XOF;
  the root helper relies on this checked caller precondition.
- Exact leaf completion before root finalization; suffix absorption before
  finalization; budget clearing before terminal output or reader publication.
- Retained-output rehash consumption before clearing all 1,024 output bytes;
  loading the next shape before resetting its metadata; checked budget
  subtraction and publication only after successful operations.
- Relative separation of root, leaf input, output and metadata, including
  distinct current/next shape fields. This assumes an already valid exclusive
  owner; it does not prove its original page or authority lifetime.
- A finite graph following every conditional edge of each actual root-finalizer
  checks suffix erasure on every ordinary return. It explores 57 scalar and
  52 AVX2 states, with seven returning states per route. The graph assumes
  separately reviewed callee contracts. Panic edges are explicit and do not
  count as successful cleanup or an arbitrary-exception guarantee.

The tests independently reject all 6,852 instruction-byte mutations without the
whole-population hash checker, plus 380 branch opcode/destination mutations
without the instruction-window checker. Reference, phase-constant, extent,
handler, relative-region and graph-assignment mutations are also rejected.
These arithmetic, copy and control-flow models are not native CPU execution.

### Earlier scalar copies remain a window-retirement obligation

The actual scalar setup conversion copies a 988-byte payload from owner offset
`0x84` into one branch-specific private-frame slot, then into a common private
slot, and finally into the completed root at owner offset `0x32`. The source
setup is cleared after its first copy; the old variant is dropped before root
replacement. The branch slots (`0x4c8..0x8a4` or `0x8a4..0xc80`) and common slot
(`0xe8..0x4c4`) are disjoint inside the allocated `0xc80`-byte frame.

Clearing that source does **not** establish clearing of earlier stack copies,
including separately moved header/tail fields. The checker deliberately leaves
full private-window clearing and shared runtime/ABI behavior with package 8.
No production Rust, saved image or release-gate policy changed, and no new
native enclave execution or independent retest is claimed.

### Sequential lifecycle and worker placement

The [lifecycle record](../assurance/windows-protection-observations/parallel-lifecycle-20261012.json)
adds seventeen actual bodies covering scalar/AVX2 operation admission,
cancellation and owner cleanup, the scalar armed guard/quarantine, AVX2 resident
construction/destruction and two invoked handlers, and both retained worker
entries with buffer cleanup. All 163 combined tests pass on Linux and Windows
without skips; regenerated reports match, with 90 current checker bindings.
The selected contracts reject 4,831 instruction-byte mutations independently
of whole-body hashes, plus 264 branch opcode/destination mutations independently
of the instruction windows. Earlier population, leaf and framing checks are
replayed, not inferred from an older PASS record.

- The specialized phase scan handles one through six allowed phases. Sequence
  admission rejects wraparound and replay, and commits only the exact next
  value. AVX2 additionally requires the healthy Keccak authority. Tests cover
  error precedence, all phase/authority byte values, sequence boundaries and
  seeded full-width values. These are models paired with actual instruction
  contracts, not native execution of arbitrary machine states.
- Cancellation binds the actual read-only six-phase array. Successful
  cancellation clears before publishing Empty and preserves sequence history;
  invalid phase/sequence/authority quarantines. Owner clearing is not a whole
  page or padding wipe. Invoked handler destinations are bound through actual
  parent xdata, without promising arbitrary-exception cleanup.
- The AVX2 resident places its authority at page offset zero before borrowing
  it. Both embedded authority pointers retain that address; the owner occupies
  `32..3200` in a 4,096-byte page. The published handle contains only the original
  page/authority/owner pointers. Operand checks establish disjoint constructor
  copy ranges within its frame; these contain public initial state/KAT data,
  not caller secrets. Original page admission remains a caller precondition.
- Both normal retirement paths destroy the typed owner before clearing every
  page byte. Operand-derived loop checks reject gaps, duplicate offsets, wrong
  registers, values, strides, limits and back edges. The AVX2 retirement graph
  checks both leaf-state paths, conditional on callee contracts. Its exception
  handler performs typed cleanup but **does not establish full-page erasure**.
- Worker entries bind exact page identity and handle publication/removal,
  duplicate/missing-owner rejection and cleanup-buffer bounds. The linked LIVE
  objects occupy disjoint, writable, nonexecutable image storage. Buffer
  clearing and volatile observations cover exactly 1,024 payload bytes plus
  112 scalar or 128 AVX2 header bytes before the public cleanup observation.
  Earlier frame copies, ABI home space and the entire private window are not
  covered by these buffer-only checks.

The entry contracts are deliberately not conflated: AVX2 checks page-end
overflow and page/window non-overlap in Rust and quarantines an existing owner
on invalid entry. Scalar rejects invalid arguments/identity without that
quarantine behavior and does not independently check page/window non-overlap;
its original allocation/exclusivity obligations remain with the C adapter.
Neither Rust entry establishes OS residency or serialization by itself.
Package 8 retains shared C/OS, CPU-entry, runtime, cumulative-stack and full
window-retirement qualification. No production Rust, saved image or release
gate changed, and no new native enclave execution or independent retest occurred.

At this lifecycle checkpoint, request dispatch/export and transitive state/owner
composition remained open. The follow-up below covers the selected request/export
bodies; remaining caller/failure composition still needs the original allocation
and authority lifetime prerequisites. The selected normal
resident/page retirement and cancellation checks above are complete within
their stated scope; they do not close package 7 or pass 2.

## Pass 2 request admission, operation dispatch and retained export

The [request/export record](../assurance/windows-protection-observations/parallel-request-export-20261012.json)
records 176 passing tests without skips on Linux (18.593 seconds) and Windows
(26.915 seconds), matching parsed reports and 94 current checker-source
bindings. It includes the previous 163 tests and thirteen new regressions.
The population, leaf, root-framing and lifecycle reviews are freshly replayed.

Four additional actual bodies are checked: both sequential Rust receivers,
AVX2 `Header::decode` and its post-copy `check_authority` helper. Their complete
3,106 bytes have named instruction-span contracts. All instruction-byte
mutations are rejected independently of the body-hash checker; 270 branch
opcode/destination mutations are also rejected independently of those spans.

The checks cover:

- Fixed 112/128-byte header copying before any payload request; bounded payload
  length, canonical empty/nonempty source and final-bit shapes, checked
  source-end arithmetic, version, sequence, reserved and AVX2 route fields.
- The nine operation identities, exact payload/output permissions, nonzero
  begin/rehash block size, zero unused fields and full-byte update/nonterminal
  squeeze requirements. A separate declarative validator cross-checks the
  emitted unsigned-mask model at boundaries, pairwise shapes and 20,000 seeded
  mixed valid/invalid headers. These models are not native execution.
- All four indirect tables: two scalar subtables, AVX2 operation dispatch and
  AVX2 decoder identity validation. Object section permissions, complete REL32
  relocation populations, same-function targets, subtable bases and all 36
  linked destinations are checked. Every one of the 144 linked table bytes is
  individually mutated and rejected; a whole-object hash is not the only check.
- Exact call targets and operation arguments. AVX2 reloads the original placed
  owner from the same LIVE object as the outer entry, decodes the same local
  copied header again and verifies its length matches the copied payload.
  Neither receiver treats the untrusted source address as a direct Rust slice;
  copying is delegated to the fixed transport, whose contract remains separate.
- Export admission from exactly Retained/More, checked next sequence, exact
  identity/width/last-bit agreement and original-owner field offsets. Successful
  export clears all 1,024 retained bytes and shape metadata before publishing
  Reader or Empty. The scalar width bound is supplied by header validation and
  equality to the retained width; AVX2 also retains an explicit export bound.

### Copy and private-frame limits remain explicit

AVX2 checks authority **after** the authorized output copy. A subsequent
authority failure revokes/clears/quarantines the owner but does not retract
bytes already copied to the requested output. The model explicitly exercises
that ordering; neither a failed OS copy nor an authority rejection is claimed
to roll back external memory. The caller must discard output on failure.

Receiver stack copies and ABI home space remain full-private-window obligations.
These selected checks assume the original exclusive owner, serialized entry,
fixed C/OS transport and returning callee contracts. Pass 2 still requires
transitive state/owner and remaining failure/lifetime composition. Concurrent
worker qualification and three-route reconciliation remain passes 3 and 4;
shared whole-image qualification remains package 8. No production Rust, signed
image or release-gate change, new enclave execution or independent retest is
claimed by this follow-up.

## Pass 2 complete: conditional sequential family closure

The [combined sequential observation](../assurance/windows-protection-observations/parallel-sequential-20261012.json)
records **193 tests passing on each host, without skips**, with matching parsed
Linux and Windows reports and 100 current checker-source bindings. Linux took
22.101 seconds for tests / 47.479 seconds total; Windows took 31.137 / 69.387.
These are saved-object review runs, not new native enclave executions.

The remaining 43 bodies (19 scalar / 24 AVX2, 17,271 bytes) now have complete
actual-COFF instruction and branch contracts. Every byte is independently
mutated without relying on the population hash; 958 branch opcode/destination
mutations are also rejected. The preceding complete-population campaign rejects
77,211 byte mutations across all three images, but does **not** promote the
concurrent image to semantic closure. Earlier primitive and selected-path
checks are executed again, not replaced by historical PASS records.

The new review covers:

- Root/leaf state construction, update and squeeze; owner begin, customization,
  update and squeeze; input/state destruction; public-length encoding and exact
  prefix completion. Identity 1/3 selects rate 168 and identity 2/4 rate 136.
  The root uses the exact 96-bit `ParallelHash` function name; leaf N/S are empty.
- All remaining linked dispatch tables, phase/rate/padding constants and every
  lane of the accelerated public zero-state startup KAT. Existing primitive
  constants must still match the prior reviewed helper image.
- One explicitly renamed destructor and three same-body helpers with narrower
  LLVM argument ranges. No attributes are dropped to make them match. Current
  request limits, CV widths, suffix bounds and guarded bit offsets discharge
  their narrower private preconditions; equal bytes alone are insufficient.
- Five remaining accelerated cleanup funclets, bound to their actual parent
  xdata. Parent guard/owner slots retain the original placed owner, not a moved
  temporary. The setup funclet destroys its active temporary; it does not claim
  to erase earlier copies in the private window.
- Original owner/authority storage, bounded payload and retained-output
  lifetimes, separate root/input/output regions and nonoverlapping constructor
  copy buffers. Update's private `length * 8` is reached only through the
  receiver's 1,024-byte bound. Original authority pointer values survive state
  transfers and remain live until typed borrowers are destroyed.
- Checked budget and 128-bit counters, exact prefix completion, terminal output
  shape, full scalar scratch clearing on ordinary returning paths, and
  quarantine on post-admission failures. Terminating panic bridges are assigned
  explicitly; termination is not counted as successful returning cleanup.

Independent finite models exercise all input/output shape boundaries, canonical
tail-byte values, integer-encoding transitions, u128 prefix sizes, the scalar
modulo-136 lowering, expected-count mismatches, budget/bit overflow, narrowed XOR
shift domains and allocation overlaps. They supplement the machine-code review;
they are not emulation of the complete Windows image or a generic compiler proof.

### Meaning of conditional closure

All 134 sequential bodies are assigned, all invoked Rust handlers are accounted
for, and the family-level helper, framing, caller, failure and typed-lifetime
obligations are reconciled. This is **author review**, not independent
cryptographic verification, production signing or full Windows qualification.

The exact pre-existing package 8 prerequisites remain: original C/OS page and
window admission, exclusive serialized entry, the complete accelerated CPU
bundle, runtime memory/division/stack-probe and SDK contracts, Win64 preservation,
cumulative private-stack bounds, and whole-window/exceptional retirement.
Earlier moved copies, padding and caller spills are not declared erased by a
typed destructor. Post-copy authority rejection still cannot retract output;
callers must discard output on any failure. No release-gate policy changed.

Next is the concurrent route (Pass B), followed by the three-route reconciliation
(Pass C). Package 7 therefore remains open even though both sequential routes
have reached their conditional family exit criterion.

## Pass 3 complete: conditional concurrent family closure

The [concurrent observation](../assurance/windows-protection-observations/parallel-concurrent-20261012.json)
records 209 tests on each host, without skips, matching parsed reports and 103
current checker-source bindings. Linux took 23.625 seconds for tests / 49.761
seconds total; Windows took 32.674 / 72.113. The complete sequential review was
replayed before accepting helper reuse.

All 64 concurrent Rust bodies and four cleanup funclets are assigned. Twenty-three
helpers match the sequential AVX2 body, references, ABI and constants exactly.
Six same-body ABI differences are explicitly reconciled, including bounded copy
and wipe ranges; debug-node renumbering does not remove other ABI attributes.
The remaining 15 bodies have full instruction contracts covering 2,561 bytes,
with 2,561 independent byte mutants and 184 branch mutants rejected.

The composition review binds all seven mutable globals to actual signed-image
instruction operands, zero initialization, distinct aligned storage and original
root/worker allocations. It covers per-worker authority, bounded leaf inputs,
generation and slot provenance, join-before-reuse, ordered CV reduction, partial
failure, cancellation, exact completion and output declassification. The actual
COFF cleanup handler is `dtor$55`; the separately emitted listing's `dtor$54` is
not accepted as evidence for this image. All four parent-to-handler xdata edges
are checked.

A finite model enumerates 680 linearized atomic gate states, including early
closure, unsuccessful workers and receipt publication before live-ticket
release. It does not prove a universal weak-memory or Windows scheduler model.
Slot/publication clearing and native joining remain explicit retirement
preconditions, not properties inferred from a successful receipt alone.

This closes the concurrent Rust-family review conditionally on the same shared
package 8 contracts. It does not establish native execution, production signing,
whole-window erasure, arbitrary exception cleanup or independent qualification.
Failed output copies may expose a prefix; callers must discard failed output.
Pass C remains the combined three-route reconciliation, not another helper pass.

## Reproduce the author checks

The saved development artifacts live outside `target/` and are not distributed
with the source. Supply their directory explicitly:

```sh
python3 scripts/cryptography/windows_enclave_parallel_reuse.py SAVED_DIRECTORY --mutate
python3 scripts/cryptography/test-windows-enclave-parallel-inventory.py SAVED_DIRECTORY
python3 scripts/cryptography/windows_enclave_parallel_leaf.py SAVED_DIRECTORY --mutate
python3 scripts/cryptography/test-windows-enclave-parallel-leaf.py SAVED_DIRECTORY
python3 scripts/cryptography/windows_enclave_parallel_framing.py SAVED_DIRECTORY --mutate
python3 scripts/cryptography/test-windows-enclave-parallel-framing.py SAVED_DIRECTORY
python3 scripts/cryptography/windows_enclave_parallel_lifecycle.py SAVED_DIRECTORY --mutate
python3 scripts/cryptography/test-windows-enclave-parallel-lifecycle.py SAVED_DIRECTORY
python3 scripts/cryptography/windows_enclave_parallel_request.py SAVED_DIRECTORY --mutate
python3 scripts/cryptography/test-windows-enclave-parallel-request.py --saved-directory SAVED_DIRECTORY
python3 scripts/cryptography/windows_enclave_parallel_sequential.py SAVED_DIRECTORY --mutate
python3 scripts/cryptography/test-windows-enclave-parallel-sequential.py --saved-directory SAVED_DIRECTORY
python3 scripts/cryptography/windows_enclave_parallel_concurrent.py SAVED_DIRECTORY --mutate
python3 scripts/cryptography/test-windows-enclave-parallel-concurrent-route.py --saved-directory SAVED_DIRECTORY
```

The tests reject missing/extra bodies or handlers, modified bytes/relocations,
wrong extents, swapped artifacts, stale source bindings, escaping source paths,
orphan functions, changed compiler ABIs and missing prior semantic checks.
They also ensure partial scheduler results cannot claim whole-image qualification
and that every remaining path stays visible. Running the test script without
saved artifacts runs only synthetic tests and explicitly skips the saved suite;
that is not a complete pass-1 validation.
