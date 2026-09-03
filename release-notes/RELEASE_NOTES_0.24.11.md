# Brynja 0.24.11 Release Notes

Status: implementation complete; complete local gate, hosted GitHub checks,
CodeQL, and signed development tag pending

## Summary

Brynja 0.24.11 closes the modern SHA-2 and SHA-3/SHAKE implementation chains
with one combined downstream acceptance boundary. All six FIPS 180-4 SHA-2
identities and all six FIPS 202 SHA-3/SHAKE identities are now recorded
**Fully implemented** across their advertised ordinary byte, canonical
arbitrary-bit, hardened public/secret, fixed-output, streaming, and XOF APIs.

This status means the complete named public families and repository-owned
acceptance evidence are present. It does not mean independent cryptographic
verification, FIPS 140-3 validation, or accelerated-backend admission.

## Deliverables

- Add a `no_std` combined consumer fixture that runs the already frozen SHA-2,
  SHA-3/SHAKE, and hardened FIPS 202 downstream boundaries together.
- Bind all twelve standardized identities, both hardened-family claims, public
  declassification, typed secret output, fixed digests, arbitrary-bit input,
  arbitrary-bit SHAKE output, irregular streaming, and incremental squeeze.
- Inventory all seven optional CPU candidates: x86 SHA, AArch64 SHA2, RV64
  Zknh SHA-256, AArch64 SHA-512, RV64 Zknh SHA-512, x86 AVX2 Keccak, and
  AArch64 SHA3 Keccak. All remain unadmitted and portable code remains the
  authoritative operational route.
- Add a fail-closed closure policy, reviewed-file hashes, and adversarial
  mutations covering status claims, backend admission, package evidence,
  supported Rust versions, `no_std` targets, standards, requirements, and
  registered secret-owner evidence.
- Synchronize the root, crates.io facade, SHA-2 leaf, SHA-3 leaf, current
  status, component inventory, standards surfaces, and requirements records.

## Verification

The repository gate runs the complete pre-existing SHA-2 and SHA-3/SHAKE
package-external fixtures before the combined fixture. Their frozen evidence
includes official vectors, byte and bit differential campaigns, streaming and
multi-squeeze partitions, length exhaustion, domain separation, forced CPU
candidate KAT/quarantine behavior, compiler artifacts, dynamic analysis,
proofs, cleanup paths, error/cancellation/recoverable-unwind/Drop behavior,
and output classification.

The combined fixture additionally proves that the final public surfaces can be
linked and exercised together from one downstream `no_std` consumer. It runs
on Rust 1.90.0 through 1.98.0 and is checked on the complete supported
cross-target matrix. A policy mutation suite must reject every claim or
evidence downgrade.

## Security And Residual Limits

- No algorithm in this release has named independent cryptographic sign-off.
- Brynja and these implementations are not FIPS 140-3 validated.
- All accelerated candidates remain unadmitted; the public default remains
  portable scalar and hardened execution is portable-only.
- Hardened cleanup covers Brynja-owned, source-declared memory through the
  compiler-resistant clearing boundary. It cannot guarantee erasure of
  registers, caches, compiler-created copies, dumps, DMA-visible memory,
  forgotten owners, aborts, forced termination, power loss, or caller-owned
  copies.
- Ordinary states are for public/unkeyed data. Secret-bearing work must use the
  distinct hardened owners, and callers remain responsible for their input and
  any copied output storage.

## Release Process

Version 0.24.11 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range. It selects zero crates for crates.io publication and
has no scheduled pentest. An exceptional assessment remains mandatory if the
final delta activates a material security trigger. After the complete local
gate passes, commit the exact candidate, wait for green GitHub and CodeQL, and
create the signed immutable `v0.24.11` tag.
