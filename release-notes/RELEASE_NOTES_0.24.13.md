# Brynja 0.24.13 Release Notes

Status: implementation complete; exceptional pentest, release reconciliation,
hosted GitHub checks, CodeQL, and signed development tag pending

## Summary

Brynja 0.24.13 implements complete KMAC128, KMAC256, KMACXOF128, and
KMACXOF256 in the new allocation-free `no_std` `brynja-mac-kmac` leaf. All
four constructions build directly over Brynja's hardened cSHAKE owner and are
reexported by `brynja-crypto` and the main `brynja` facade.

This completes the keyed instances defined by NIST SP 800-185, not the entire
SP 800-185 family. TupleHash, ParallelHash, acceleration and final combined
family acceptance remain later milestones. KMAC is not independently
cryptographically verified, Brynja is not FIPS 140-3 validated, and every
service indicator remains `NonApproved`.

## Deliverables

- Implement typed streaming and one-shot KMAC128/KMAC256 states with exact
  `KMAC` function-name separation, encoded-key bytepad, customization and
  fixed-output right encoding.
- Implement KMACXOF128/KMACXOF256 absorb and incremental reader states with
  exact XOF right encoding, checked cumulative output, typed secret output and
  explicit public declassification.
- Preserve every representable standards-valid key, message, customization and
  output bit length through explicit conformance constructors while production
  constructors require the selected 128- or 256-bit security strength.
- Expose opaque fixed tags without ordinary equality or formatting. Candidate
  verification performs content-independent work for the public candidate
  length and rejects wrong length, final-bit shape and cross-instance use.
- Register all Brynja-owned key-encoding, metadata, pending-byte, verification
  and temporary output regions for compiler-resistant destruction while the
  underlying hardened cSHAKE owner clears its own sponge state.

## Verification

- All six official NIST KMAC examples and all six official KMACXOF examples
  pass for both strengths, customization profiles and output lengths.
- A separately composed Python Keccak/cSHAKE/SP 800-185 oracle agrees on 256
  byte and arbitrary-bit combinations across all four constructions.
- Direct tests cover empty, weak, strong, boundary and long keys; streaming
  partitions; bit tails; fixed versus XOF separation; customization changes;
  invalid and partial tags; output exhaustion; typed secret destruction; and
  conformance-versus-production service status.
- A standalone package-external `no_std` consumer exercises the leaf,
  composition crate and main facade and compiles for a bare-metal target.
- Fail-closed policy binds exact source hashes, dependency direction, unsafe/
  allocation/native-code absence, public APIs, assurance limits, cleanup,
  proofs, differential evidence, and malformed-input rejection.
- The local evidence suite includes twenty-two cumulative Kani bounds, Miri,
  AddressSanitizer, constant-time comparison timing, and exact Rust 1.90.0 and
  1.98.0 MIR/LLVM/assembly cleanup inspection.

## Security And Residual Limits

- Production constructors enforce full-strength keys and fixed tags;
  conformance constructors intentionally accept weaker standards-valid cases
  but identify them as non-approved.
- KMACXOF output remains secret unless returned in an affine typed owner or
  explicitly declassified. Failed secret output clears the whole destination.
- Cleanup covers Brynja-owned source-declared memory during normal, error,
  cancellation, recoverable-unwind and Drop paths. It cannot guarantee
  register, cache, compiler-copy, dump, DMA, swap, abort, forced-termination,
  power-loss, forgotten-owner or caller-owned-copy erasure.
- Callers remain responsible for keys, messages, customization, candidate tags
  and copied outputs they own.
- No accelerated KMAC route is admitted. No independent review or official
  FIPS validation certificate exists.

## Authority

The implementation is bound to the repository's pinned final NIST SP 800-185
and FIPS 202 copies. The standards lifecycle monitor records NIST's announced
SP 800-185 revision; an upstream change requires review and cannot silently
change this implementation's status.

Official results are checked against NIST's KMAC and KMACXOF sample documents.

## Release Process

Version 0.24.13 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates for crates.io publication.
The new keyed cryptographic boundary requires an exceptional pentest. After a
committed PASS/PASS report and complete local release verification, wait for
green GitHub and CodeQL, then create the signed immutable `v0.24.13` tag.
