# Brynja 0.24.14 Release Notes

Status: implementation complete; exceptional pentest, final release
reconciliation, hosted GitHub checks, CodeQL, and signed tag pending

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

## Security And Residual Limits

- The ordinary API is for public/unkeyed data. Secret-bearing tuple items or
  derived state require the distinct hardened owners.
- Hardened output remains secret unless returned in an affine typed owner or
  explicitly declassified. Failed secret output clears the whole destination.
- Cleanup covers Brynja-owned source-declared memory during normal, error,
  abandonment, cancellation, recoverable-unwind, and Drop paths. It cannot
  guarantee erasure of registers, caches, compiler-created copies, dumps, DMA,
  swap, aborts, forced termination, power loss, forgotten owners, or
  caller-owned copies.
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
The new construction and hardened ownership boundary require an exceptional
pentest before release reconciliation. After the report-bearing candidate is
green on GitHub and CodeQL, explicit repository-owner authorization may create
the signed immutable `v0.24.14` tag.
