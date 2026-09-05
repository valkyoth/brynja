# Brynja 0.24.18 Release Notes

Status: implementation candidate; exceptional pentest pending

## Summary

Complete first-party portable legacy SHA-1 is available in the new unpublished
`brynja-legacy-sha1` 0.1.0 leaf. The facade advances to internal 0.24.18 without
reexporting or enabling SHA-1. No crate is published at this milestone.

## Deliverables

- All FIPS 180-4 SHA-1 operations: byte/bit one-shot, streaming, consuming
  canonical tail finalization, checked exhaustion and 160-bit output.
- Separate sealed hardened API, explicit public declassification, affine
  secret output and failure-atomic/clearing output contracts.
- One shared first-party compression engine with six mandatory clearing
  regions, including schedule and block/padding scratch; no new unsafe or C.
- 529 official NIST bit vectors, million-byte vector, partition/boundary tests,
  independent bit oracle, malformed adapter requests and real downstream use.
- Source/mutation, MSRV, no_std, Miri/ASan, Kani length-domain, and compiler
  owner-cleanup integration. Evidence is recorded only after checks run.

## Compatibility and security

SHA-1 is collision-broken, not suitable for new security designs, and not a
MAC, password hash, signature or protocol admission. No modern/default,
general-hash, TLS, PKIX or FIPS edge is introduced. Future legacy constructions
must apply separately typed admission. Existing modern production Rust is
unchanged; only generic first-party core/hash-core dependencies are used.

Both API states clear their owned regions, but only hardened output enforces
secret classification. Caller copies, compiler copies/spills, registers,
caches, swap, dumps, DMA, moves, abort, forget and forced termination are
residual risks. Memory hardening does not repair SHA-1 collisions.

SHA-1 remains **In progress** until the later portable consumer, acceleration
disposition and final-family acceptance passes. No named independent review
or FIPS validation is claimed. Rust 1.90.0–1.98.1 compatibility remains required;
latest stable default checks use 1.98.1, while Kani uses its declared older Rust.

## Release conditions

Exceptional pentest, local release check, report commit, green GitHub/CodeQL,
then explicit owner permission to tag. This is an internal development tag
and the publication plan must remain empty. No tag or push is made while
preparing the implementation candidate.

See [SHA-1 assurance](../docs/legacy-sha1.md) and
[pentest record](../security/pentest/v0.24.18.md).
