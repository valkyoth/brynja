# Brynja 0.24.11 Release Notes

Status: implementation and local release verification complete; voluntary
pentest and retest PASS; hosted GitHub checks, CodeQL, and signed development
tag pending

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

## Security Assessment

The voluntary v0.24.11 assessment found no Critical, High, or Medium security
vulnerability. It identified one non-security documentation inconsistency:
the component table recorded both families as fully implemented while later
present-tense prose still described combined acceptance as pending. Remediation
commit `5074b35eb759ff69f83c8188588bf6da61a9e5ee` corrected the prose and added
negative regression fixtures. The repository-owner retest is fully green, and
the permanent [v0.24.11 report](../security/pentest/v0.24.11.md) records
`PASS`/`PASS` with zero open findings.

The same remediation reserves an optional high-assurance protected-memory
layer for v0.126.1-v0.126.5. That is roadmap work, not an implemented v0.24.11
capability or a stronger erasure claim.

The post-retest live release gate detected newly reported technical RFC 9846
erratum 9161. Human review confirms that it clarifies presentation syntax
versus the existing conforming `signature_algorithms` sender requirement and
changes no wire rule or sender behavior. It remains unverified and
`track-not-applied`; the refreshed 294-record errata projection, source ledger,
authority register and September 3 freshness receipt admit no TLS code or
requirement change.

## Release Process

Version 0.24.11 is an internal development milestone in the cumulative
v0.20.0-to-v0.25.0 range. It selects zero crates for crates.io publication.
Although no scheduled assessment was required, its voluntary assessment and
retest are complete. After this report-bearing candidate passes the complete
local gate, wait for green GitHub and CodeQL, then create the signed immutable
`v0.24.11` tag.
