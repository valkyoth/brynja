# Brynja 0.24.12 Release Notes

Status: implementation, pentest remediation, exceptional retest, and complete
local release verification passed; hosted GitHub checks, CodeQL, and signed
development tag pending

## Summary

Brynja 0.24.12 implements all four NIST SP 800-185 encoding operations and
complete cSHAKE128/cSHAKE256 APIs. The allocation-free `no_std` implementation
supports byte and canonical arbitrary-bit function names, customization,
messages and output; exact empty-name-and-customization SHAKE equivalence;
one-shot, streaming, fixed-output and incremental XOF use; and distinct
hardened secret-bearing owners.

This completes cSHAKE, not the entire SP 800-185 family. KMAC, TupleHash,
ParallelHash and final combined family acceptance remain planned through
v0.24.17. cSHAKE is not independently cryptographically verified, Brynja is
not FIPS 140-3 validated, and no accelerated backend is admitted.

## Deliverables

- Implement canonical `left_encode`, `right_encode`, `encode_string`, and
  `bytepad` over the complete SP 800-185 integer domain below 2^2040, checked
  bit-length arithmetic and exact caller-owned destinations.
- Implement cSHAKE128 and cSHAKE256 with exact N/S encoding, the `00` cSHAKE
  domain suffix, and exact SHAKE behavior when both N and S are empty.
- Expose ordinary one-shot, streaming, arbitrary-bit, fixed-output and
  incremental squeeze APIs from `brynja-hash-sha3`, `brynja-crypto`, and the
  `brynja` facade.
- Expose distinct hardened cSHAKE absorb/read states using the registered
  FIPS 202 owner, compiler-resistant cleanup, explicit public declassification
  and typed secret output.
- Add bounded package-external and differential assurance fixtures, extend
  Rust-version and bare-metal matrices, inventory twenty cumulative Kani
  bounds, and bind cSHAKE source, tests, dynamic analysis and malformed-input
  rejection into fail-closed policy.

## Verification

- All four official NIST cSHAKE examples for short and 1600-bit messages pass.
- Empty N/S agrees exactly with SHAKE across multi-rate output, while nonempty
  customization and the two strengths remain domain-separated.
- A separately coded Keccak/SP 800-185 oracle agrees on 480 arbitrary-bit
  combinations spanning N, S, message, rate boundaries and output boundaries.
- Streaming absorption, irregular incremental squeezing, arbitrary-bit output,
  encoding boundaries, complete integer bounds, transactional rejection, and
  hardened secret-output destruction have direct tests.
- A standalone `no_std` consumer exercises the leaf, composition crate and
  main facade ordinary and hardened APIs against an official result.
- The full repository gate covers supported Rust 1.90.0 through 1.98.0,
  supported hosted and bare-metal targets, warnings-denied Clippy, packaging,
  source mutations, Miri, AddressSanitizer and local tag-gate Kani evidence.

## Pentest Remediation

The initial exceptional assessment reported one Medium sensitive-metadata
remanence finding. Hardened cSHAKE kept its customization discriminator and
encoded setup length in wrapper fields outside the registered clearing owner.
The remediation removes both wrapper fields, adds byte-backed domain and setup
regions to `HardenedFips202Owner`, clears them on finalization and every owner
Drop path, and expands owner-shape, mutation, unit, MIR, LLVM IR, assembly and
Rust 1.90.0/1.98.0 evidence from eleven to thirteen registered regions. The
exceptional retest of exact remediation candidate
`16539b17eff0b33282a0eeeb6708be21dc127973` passed with zero open findings. The
[permanent report](../security/pentest/v0.24.12.md) records `PASS`/`PASS`.

## Security And Residual Limits

- Ordinary cSHAKE state is for public/unkeyed data and does not promise erasure
  of absorbed data or private working state. Secret-bearing use selects the
  hardened cSHAKE owner.
- Hardened cleanup covers Brynja-owned source-declared memory during normal,
  error, cancellation, recoverable-unwind and Drop paths. It cannot guarantee
  register, cache, compiler-copy, dump, DMA, swap, abort, forced-termination,
  power-loss, forgotten-owner or caller-owned-copy erasure.
- Caller-owned N, S, input and copied output remain caller responsibilities.
- No named independent reviewer has signed off on cSHAKE or its shared
  permutation, and no FIPS validation certificate exists.

## Authority

The implementation is bound to the repository's pinned final NIST SP 800-185
and FIPS 202 copies. The standards lifecycle monitor also records NIST's
announced SP 800-185 revision state; an upstream change requires review and
cannot silently reclassify this implementation.

Official examples were checked against NIST's [cSHAKE sample document](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/cSHAKE_samples.pdf).

## Release Process

Version 0.24.12 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range and selects zero crates for crates.io publication.
Adding cryptographic code requires an exceptional pentest. After a committed
PASS/PASS report and complete local release verification, wait for green GitHub
and CodeQL, then create the signed immutable `v0.24.12` tag.
