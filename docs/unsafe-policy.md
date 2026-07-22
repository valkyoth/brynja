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
