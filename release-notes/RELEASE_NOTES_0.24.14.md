# Brynja 0.24.14 Release Notes

Status: implementation and pentest remediation complete; independent retest,
final release reconciliation, hosted GitHub checks, CodeQL, and signed tag pending

## Summary

Brynja 0.24.14 implements complete TupleHash128, TupleHash256,
TupleHashXOF128, and TupleHashXOF256 in the new allocation-free `no_std`
`brynja-hash-tuple` leaf. All four constructions build over Brynja's hardened
cSHAKE owner and are reexported by `brynja-crypto` and the main `brynja`
facade.

This completes TupleHash, not the entire SP 800-185 family. ParallelHash and
the combined derived-family acceptance remain later milestones. TupleHash is
not independently cryptographically verified, Brynja is not FIPS 140-3
validated, and no accelerated backend is admitted.

## Deliverables

- Implement distinct streaming and one-shot TupleHash128/TupleHash256 states
  with exact `TupleHash` function-name separation, customization, per-item
  `encode_string`, and fixed-output terminal encoding.
- Implement TupleHashXOF128/TupleHashXOF256 absorb and incremental reader
  states with exact XOF terminal encoding, checked cumulative output, ordinary
  public output, hardened typed-secret output, and explicit declassification.
- Accept complete byte strings and canonical arbitrary-bit strings as ordered
  tuple items without flattening item boundaries or exposing cSHAKE or Keccak
  internals.
- Expose an affine exact-length streamed-item writer. An item must consume its
  declared bit count before completion; underflow, overflow, or abandonment
  permanently closes the parent tuple state.
- Preserve empty tuples, empty items, tuple order, item partition identity,
  customization, non-byte tails, and arbitrary-bit fixed or XOF output.
- Register and compiler-check the hardened TupleHash owner. Its cSHAKE state,
  pending item byte, bit width, item count, failure latch, reader state, and
  output staging are cleared through Brynja's mandatory cleanup boundary.
- Keep finalization in the caller-owned TupleHash allocation: fixed-output
  methods borrow the state, XOF finalization returns a lifetime-bound reader,
  and no secret-bearing cSHAKE owner is returned or transferred by value.
- Clear every no-longer-needed byte-backed metadata field before successful
  fixed finalization returns or an XOF borrowing reader escapes, including the
  tuple count, pending byte, bit width, remaining-item length, and failure
  latch.

## Verification

- All twelve official NIST TupleHash and TupleHashXOF examples pass for both
  strengths, customization profiles, and output modes.
- A separately composed Python Keccak/cSHAKE/SP 800-185 oracle agrees on 256
  bounded byte and arbitrary-bit cases across all four constructions.
- Tests distinguish `("ab", "c")`, `("a", "bc")`, one `"abc"` item,
  reordered items, empty items, and altered customization.
- Direct tests cover whole versus streamed items, incomplete and abandoned
  item failure, boundary-crossing input, fixed output, partitioned XOF output,
  non-byte output, destination policy, and hardened-output destruction.
- A standalone package-external `no_std` consumer exercises the leaf,
  composition crate, and main facade and compiles for the bare-metal policy
  target.
- Fail-closed policy binds exact source hashes, dependency direction,
  allocation/unsafe/native-code absence, public APIs, item lifecycle,
  arbitrary-bit behavior, cleanup, official examples, differential evidence,
  malformed-input rejection, and package contents.
- The local evidence suite includes twenty-four cumulative Kani bounds,
  focused Miri and AddressSanitizer coverage, and exact Rust 1.90.0/1.98.1
  development and optimized MIR, LLVM IR, and assembly cleanup inspection.
- Compiler evidence inspects `Backend::finalize_in_place`,
  `TupleCore::finish_in_place`, and package-external finalization-only fixed and
  streaming calls. A self-test proves the matcher rejects representative
  1040–1042-byte owner allocas and LLVM copies, while the isolated external
  functions reject every LLVM or assembly memcpy.

## Pentest Remediation

The initial exceptional assessment found two High secret-state remanence
issues, two Medium item-lifecycle and metadata-remanence issues, and two Low
assurance/defensive-code observations. A later retest found that one High
owner-copy path remained and that the compiler gate did not observe it. The
next retest confirmed the High path was fixed, but found one Medium
post-finalization tuple-count remanence issue and one Medium false-negative in
the LLVM/assembly matcher. The complete remediation:

- transitions the exact embedded cSHAKE owner from absorption to squeezing in
  place, returns only lifetime-bound borrowing TupleHash readers, finalizes
  fixed output through `&mut self`, makes reuse fail closed, and gives every
  borrowing reader an in-place clearing Drop path;
- finalizes a partial tuple item directly from the registered pending byte,
  without copying it into an uncleared local array;
- arms the parent item-open failure latch before any writer is returned and
  clears it only after exact completion, so `mem::forget` and `ManuallyDrop`
  cannot authorize a malformed TupleHash output;
- stores streamed remaining length in byte-backed clearing owner storage and
  stages left/right encoded lengths in a dedicated owner whose Drop clears its
  bytes and width; and
- clears all five source-owned metadata regions at the successful transition
  to squeezing and proves through ordinary and hardened fixed/XOF APIs that
  the tuple count is no longer observable after the finalization borrow; and
- replaces the numeric backend fallback with a closed strength enum, makes the
  Kani reservation proof execute the production checked-subtraction path over
  the complete `u128` domain, and compiles a package-external harness before
  rejecting secret-owner-sized LLVM copies. The corrected matcher is exercised
  by synthetic positive and negative fixtures, and finalization-only external
  functions reject any LLVM or assembly memcpy.

Permanent regressions cover forgotten writers, exact in-place phase changes,
borrow-scoped readers, irreversible reuse rejection, post-finalization
metadata erasure, clearing encoders, backend strength, partial-byte ownership,
the production proof path, matcher self-tests, and every compiler-evidence
edge. Development and optimized MIR, LLVM IR, and assembly checks bind the
exact finalization functions and isolated external consumer boundary to the
no-copy rule and subsequent owner wipe. Independent retest of the exact
remediation candidate is required before the release status can become PASS.

## Security And Residual Limits

- The ordinary API is for public/unkeyed data. Secret-bearing tuple items or
  derived state require the distinct hardened owners.
- Hardened output remains secret unless returned in an affine typed owner or
  explicitly declassified. Failed secret output clears the whole destination.
- Cleanup covers Brynja-owned source-declared memory during normal, error,
  abandonment, cancellation, recoverable-unwind, and Drop paths. The reviewed
  TupleHash transitions reject known owner-sized compiler copies, but portable
  Rust cannot guarantee erasure of every register, cache, unobserved compiler
  temporary, dump, DMA or swap copy, nor cleanup after abort, forced
  termination, power loss, forgotten owners, or caller-owned copies.
- Callers remain responsible for tuple items, customization, and copied output
  they own.
- No independent review, FIPS validation certificate, or accelerated
  TupleHash route exists.

## Authority

The implementation is bound to the repository's pinned final NIST SP 800-185
and FIPS 202 copies. The standards lifecycle monitor records NIST's announced
SP 800-185 revision; an upstream change requires review and cannot silently
change this implementation's status.

Official results are checked against NIST's TupleHash and TupleHashXOF sample
documents. The retrieved PDF SHA-256 identities are respectively
`7d4491c28e6dcf4751975e6f15ec73c8b4a676a3b653d524e7561e3141cc6465`
and `c3be9c3891bfad850347ff5664e504cbbd832c4d942b98aec48555a1a390678c`;
these evidence inputs are not a claim of independent verification.

## Release Process

Version 0.24.14 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates for crates.io publication.
The new construction and hardened ownership boundary required an exceptional
pentest. Its initial and retest findings are remediated, but independent retest remains mandatory
before release reconciliation. After the retested report-bearing candidate is
green on GitHub and CodeQL, explicit repository-owner authorization may create
the signed immutable `v0.24.14` tag.
