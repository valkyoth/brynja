# Windows ParallelHash family review

Package 7 is **open**. This is a saved-image author review, not a release gate,
new native enclave run, independent retest or whole-image qualification.
Production Rust, signed images and release-gate policy are unchanged.

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

Still required in pass 2: state/owner caller composition, customization/rehash,
final-output framing and retention, original allocation/non-alias lifetimes,
remaining failure paths and full resident/page retirement. These selected
checks do not remove the enclosing caller obligations or close package 7.

## Reproduce the author checks

The saved development artifacts live outside `target/` and are not distributed
with the source. Supply their directory explicitly:

```sh
python3 scripts/cryptography/windows_enclave_parallel_reuse.py SAVED_DIRECTORY --mutate
python3 scripts/cryptography/test-windows-enclave-parallel-inventory.py SAVED_DIRECTORY
python3 scripts/cryptography/windows_enclave_parallel_leaf.py SAVED_DIRECTORY --mutate
python3 scripts/cryptography/test-windows-enclave-parallel-leaf.py SAVED_DIRECTORY
```

The tests reject missing/extra bodies or handlers, modified bytes/relocations,
wrong extents, swapped artifacts, stale source bindings, escaping source paths,
orphan functions, changed compiler ABIs and missing prior semantic checks.
They also ensure partial scheduler results cannot claim whole-image qualification
and that every remaining path stays visible. Running the test script without
saved artifacts runs only synthetic tests and explicitly skips the saved suite;
that is not a complete pass-1 validation.
