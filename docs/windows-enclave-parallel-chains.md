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

## Reproduce the author checks

The saved development artifacts live outside `target/` and are not distributed
with the source. Supply their directory explicitly:

```sh
python3 scripts/cryptography/windows_enclave_parallel_reuse.py SAVED_DIRECTORY --mutate
python3 scripts/cryptography/test-windows-enclave-parallel-inventory.py SAVED_DIRECTORY
```

The tests reject missing/extra bodies or handlers, modified bytes/relocations,
wrong extents, swapped artifacts, stale source bindings, escaping source paths,
orphan functions, changed compiler ABIs and missing prior semantic checks.
They also ensure partial scheduler results cannot claim whole-image qualification
and that every remaining path stays visible. Running the test script without
saved artifacts runs only synthetic tests and explicitly skips the saved suite;
that is not a complete pass-1 validation.
