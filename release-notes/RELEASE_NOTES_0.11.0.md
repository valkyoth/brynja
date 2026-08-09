# Brynja v0.11.0 Development Milestone

Status: remediation complete; exceptional pentest retest required; not yet tagged

Brynja v0.11.0 is the first tagged development milestone in the five-minor
release train ending at public checkpoint v0.15.0. It advances the `brynja`
facade version and will receive a signed tag only after its complete automated
gate and green GitHub and CodeQL. It selects no crate for crates.io
publication. Because it introduces the first isolated unsafe
secret-destruction primitive, the exceptional-trigger policy requires a
committed PASS pentest before the tag.

## Implemented Scope

`brynja-core` now provides a safe affine state machine over one non-empty,
exclusively borrowed caller allocation. Admission clears prior bytes,
initialization is write-only and sequential, readable ownership requires exact
completion, and incomplete finish, both Drop paths, and explicit clear execute
the complete-region primitive.

The primitive contains one private unsafe block: every pointer is derived from
a live exclusive byte reference, one volatile zero store is performed, no raw
pointer is retained or offset, and a compiler barrier follows the loop.
Repository policy rejects all other unsafe allowances, blocks, items, assembly,
and FFI.

Evidence checks the volatile call in MIR, the volatile zero store in LLVM IR,
and a byte store in assembly for Rust 1.90.0 through 1.97.1 and all nine
promised targets. Pinned Miri and AddressSanitizer execute every owned-memory
integration test.

The claim covers only the bytes in that complete Rust allocation when clearing
returns. Registers, caller- or compiler-created copies, CPU/device caches,
DMA-visible copies, dumps, suspend images, physical-memory remanence,
concurrent access, `mem::forget`, abort, and process or power termination are
excluded. Platform cache, DMA, external-store, and accelerator completion
remain separate destruction duties.

The initial exceptional assessment found a Medium bypass in the repository's
unsafe-policy scanner, not in the production zeroization implementation. The
approved unsafe module is now pinned by exact SHA-256, any byte change reopens
review, and every other Rust source rejects all unsafe tokens, unsafe-code
allow/expect overrides, whitespace-varied FFI or assembly syntax, symlinked
source, and `include!` code injection. Regression fixtures reproduce the two
reported bypass classes and additional assembly and inclusion variants. Local
remediation is complete and awaits repository-owner retest.

## Cumulative Pentest Coverage

The next scheduled assessment is v0.15.0. It will pentest backwards over all
changes after public tag v0.10.0 through the exact v0.15.0 candidate, including
v0.11.0 and every intervening minor or patch milestone. The following v0.20.0
assessment will cover changes after v0.15.0 through v0.20.0.

This milestone's exceptional assessment does not remove any change from the
next scheduled cumulative checkpoint.

## Publication

No package is selected. The latest crates.io facade remains `brynja 0.10.0`;
supporting crates retain their independently published versions.
