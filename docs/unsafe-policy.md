# Unsafe Rust Policy

Status: unsafe forbidden

Workspace lints forbid unsafe code. No exception exists in `0.1.0`.

A future exception requires a versioned milestone, written necessity analysis,
safe alternative analysis, isolated module or crate, documented invariants,
Miri/sanitizer and adversarial tests, platform review, an external audit, and
explicit amendment of this policy. Assembly and FFI are treated as unsafe even
when hidden behind build tooling.

