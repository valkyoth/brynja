# Brynja 0.24.18 Release Notes

Status: exceptional retest and full local release check passed; awaiting green GitHub/CodeQL and owner tag authorization

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

## Pentest hardening

The supplied review identified two Low/informational observations, not an
exploitable SHA-1 defect. Debug builds now assert the private buffer-offset
invariant before absorption and padding writes. Regression tests inject all
invalid byte offsets and cover valid block boundaries; release-code inspection
checks that these debug diagnostics are absent when debug assertions are off.
Cleanup itself remains non-panicking. This is a development diagnostic, not
release-mode detection of corrupted private state.

Byte-at-a-time absorption remains linear and unchanged. Bulk-copy optimization
is deferred to performance work with measurement and equivalent cleanup tests;
no throughput improvement or CPU admission is claimed here.

## Release conditions

The owner-supplied retest of v0.24.17 through 351c9292 reported no Critical,
High or Medium findings. The permanent report records PASS/PASS with zero
open findings. This is not named independent cryptographic review or FIPS
validation. The reviewer's online toolchain probe was blocked by sandbox DNS;
the local release check independently completed that online freshness stage.

The complete repository gate, twelve Rust lanes, three bare-metal targets,
supplemental QEMU/timing checks, all eight full Miri groups, full AddressSanitizer
wrapper and all twenty-six Kani harnesses passed. Miri groups ran in isolated
parallel caches; no group was omitted. LeakSanitizer remains excluded because
of the documented ptrace restriction. Standards/live-authority, tool freshness,
dependency admission, RustSec, cargo-deny, SBOM and protected-release controls
also passed. The publication check/dry-run selects zero crates, including
changed support crates; all thirty-three publishing-policy regressions pass.

No Rust, dependency, toolchain or publication selection changed after the
reviewed 351c9292 commit. This release-check reconciliation updates only
documentation and its reviewed metadata bindings.

Exceptional pentest, local release check, report commit, green GitHub/CodeQL,
then explicit owner permission to tag. This is an internal development tag
and the publication plan must remain empty. No tag or push is made while
preparing the implementation candidate.

See [SHA-1 assurance](../docs/legacy-sha1.md) and
[pentest record](../security/pentest/v0.24.18.md).
