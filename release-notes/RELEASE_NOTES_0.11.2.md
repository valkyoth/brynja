# Brynja v0.11.2 Development Milestone

Status: exceptional assessment PASS; awaiting green GitHub and CodeQL

Brynja v0.11.2 implements the optional sanitization adapter admitted at
v0.11.1. It advances the `brynja` facade to 0.11.2, selects no crate for
crates.io publication, and remains in the cumulative release train ending at
v0.15.0.

This candidate also reconciles the future implementation roadmap before the
cryptographic phase begins. Portable scalar implementations remain the no_std
default. Future ISA kernels live in a separate optional no_std CPU package,
standard-library runtime detection lives in a narrower opt-in adapter, and
each primitive receives bounded architecture-specific implementation and
qualification stops rather than one oversized SIMD milestone. Native evidence
is planned for local AMD x86_64, observed-feature AWS Intel x86_64, Apple M2,
AWS AArch64, and qualifying RISC-V hardware; QEMU remains supplemental and an
unavailable feature bundle remains an explicit candidate or scalar-only path.

The roadmap now also makes first-party Rust cryptography the permanent golden
rule. Every Brynja primitive, construction, key operation, protocol
cryptographic operation, CPU backend, and FIPS module service must be a
Brynja-owned Rust implementation rather than a C/native wrapper or delegated
software provider. Machine checks reject foreign source and binary artifacts,
build scripts and dependencies, Cargo native links, foreign ABIs, and included
native binaries.

Future `brynja-rustls` and `brynja-tokio` packages are planned as separately
locked downstream companion adapters. Applications will select them directly;
they can never enter the main facade, engine, crypto, default, legacy,
bare-metal, or FIPS-module graph. The rustls adapter will disable every built-in
provider and use Brynja cryptography throughout. The Tokio adapter will wrap
Brynja's TLS engine rather than rustls or a raw AEAD stream.

## Adapter Boundary

The new separately publishable `brynja-sanitization 0.1.0` package exact-pins
first-party `sanitization 2.0.3`, disables default features, selects no feature,
and resolves no transitive package. `SanitizedSecret<N>` owns upstream
fixed-size storage behind an opaque, non-copyable wrapper with redacted debug
output, closure-scoped inspection, explicit clear, transactional replacement,
and a payload-free `SourceFailure` boundary.

Named copy operations bridge exact-length `brynja-core` owned regions. A
successful copy deliberately creates two owners, and each clears only its own
storage. Length, source, and initialization errors carry no bytes, offsets,
length values, text, or arbitrary caller payloads.

## Isolation

Applications must select the adapter directly. The `brynja` facade, modern and
legacy protocol engines, platform adapter, default and all-features aggregates,
and future FIPS validated-module closure do not depend on or activate it. One
protocol-neutral type serves modern and legacy downstream callers; no
`brynja-legacy-sanitization` package exists.

Workspace metadata and lock policy admit only the reviewed external package,
source, version, owner, zero-feature set, and empty transitive graph. Broken
fixtures reject floating pins, upstream defaults and features, facade reach,
wrong external identity, `zeroize`, and every unadmitted external package.

## Verification And Limits

Tests cover construction, empty size, every source-failure position,
transactional replacement, exact and wrong region capacities, both copy
directions, redaction, explicit clear, Drop, shared modern/legacy use,
upstream differential behavior, unwind, and compile-fail Clone, rich-error,
conversion, and escaping-borrow attempts. The workspace matrix covers Rust
1.90.0 through 1.97.1 and every promised target. Pinned Miri executes the
adapter tests, while release-built MIR, LLVM IR, and assembly retain the
explicit-clear path and volatile zero stores.

These checks are evidence, not independent cryptographic verification or FIPS
validation. Cleanup after abort, forced termination, `mem::forget`, prior
copies, registers, caches, DMA, dumps, swap, hibernation, privileged reads, and
physical attacks remains outside the claim.

## Release Process

The first production wrapper around external unsafe secret-storage code is a
material boundary, so v0.11.2 received an exceptional repository-owner
assessment. The result was PASS/PASS with zero findings and zero open findings;
the permanent report is committed at `security/pentest/v0.11.2.md`. It remains
an internal development milestone with zero crates.io selections. After the
exact signed release-preparation commit passes the complete local gate and
GitHub and CodeQL are green, the immutable signed `v0.11.2` tag may be created.
The work also remains in the later v0.10.0-through-v0.15.0 cumulative review
scope.
