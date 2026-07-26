# Unsafe Rust Policy

Status: unsafe forbidden

Workspace lints forbid unsafe code. No exception exists in `0.1.0`.

A future exception requires a versioned milestone, written necessity analysis,
safe alternative analysis, isolated module or crate, documented invariants,
Miri/sanitizer and adversarial tests, platform review, an external audit, and
explicit amendment of this policy. Assembly and FFI are treated as unsafe even
when hidden behind build tooling.

Production admission requires reviewed destruction of every complete owned
secret memory region. The planned zeroization milestone may justify only the
smallest isolated primitive needed to preserve stores through optimization.
Its proof must cover every supported compiler and target plus platform cache
and DMA completion duties. Claims must disclose limits for registers, copies,
crash dumps, and physical memory, but a weaker owned-region guarantee cannot
pass the `1.0.0` gate. This paragraph does not itself authorize unsafe code.

The v0.11.1 review treats unsafe code inside the exact `sanitization` release as
part of the adapter's inherited trusted computing base. Admission requires the
same necessity, invariant, Miri, emitted-code, target, and external-review
evidence expected of a local exception. Approval applies only to the separately
selected `brynja-sanitization` adapter and does not authorize additional unsafe
code or replace Brynja's mandatory v0.11.0 primitive.
