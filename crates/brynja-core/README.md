<p align="center">
  <b>Security-first, first-party Rust, no_std cryptography and secure protocols.</b><br>
  Built in small reviewable releases with strict modern, legacy, and research isolation.
</p>

<div align="center">
  <a href="https://crates.io/crates/brynja">Crates.io</a>
  |
  <a href="https://docs.rs/brynja">Docs.rs</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/RELEASE_PLAN.md">Release Plan</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md">Threat Model</a>
  |
  <a href="https://github.com/valkyoth/brynja/blob/main/SECURITY.md">Security</a>
</div>

<br>

<p align="center">
  <a href="https://github.com/valkyoth/brynja">
    <img src="https://raw.githubusercontent.com/valkyoth/brynja/main/.github/images/brynja.webp" alt="Brynja security-first Rust cryptography and secure protocols overview">
  </a>
</p>

# brynja-core

Allocation-free `no_std` security foundations shared by Brynja's crypto and
protocol crates. This crate owns bounded state and authority contracts, not a
TLS engine or collection of hash/cipher implementations.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Checked counters, budgets, transactional cursors and typed workspaces | ✅ Implemented | ❌ No |
| Owned secret regions and compiler-resistant clearing | ✅ Implemented | ❌ No |
| Fixed-width constant-time equality, selection and swap | ✅ Implemented | ❌ No |
| Provider, entropy, clock, pending-operation and security-outcome contracts | ✅ Implemented contracts | ❌ No |
| Bounded observational security events | ✅ Implemented | ❌ No |
| OS providers, DRBGs and executable FIPS module | ❌ Not implemented | ❌ No |

Tests, emitted-code checks and pentests are not named independent review.
Brynja is not FIPS 140-3 validated.

## Use

For published foundations, let Cargo select the available package:

```sh
cargo add brynja-core --no-default-features
```

Use a path dependency when testing unpublished checkout changes.

```rust
use brynja_core::SecretRegionInitialization;
let mut storage = [0xa5; 4];
{
    let mut initialization = SecretRegionInitialization::begin(&mut storage).unwrap();
    initialization.write(&[1, 2, 3, 4]).unwrap();
    let secret = initialization.finish().unwrap();
    assert_eq!(secret.expose(), &[1, 2, 3, 4]);
}
assert_eq!(storage, [0; 4]);
```

Initialization clears the whole admitted region; only complete initialization
produces a readable owner. Failed writes preserve live state. Incomplete
initialization, explicit clearing and Drop erase the complete allocation.

`ReadCursor` and `WriteCursor` preflight ranges before advancing; failed
writes preserve output. Named builders require every limit exactly once.
Typed workspace domains prevent swapping secret/plaintext/transcript/
certificate/output arenas, but a domain label alone does not clear memory.

Fixed-width `Choice`/`CtMask` operations avoid exposing ordinary equality
or formatting. `Choice::expose_public` explicitly reveals a result.
Content-independent emitted code is checked within a compiler/target matrix;
this is not a blanket microarchitectural timing guarantee.

## Authority contracts

Provider requests bind exact operation, identity, limits and destruction duties.
Entropy wrappers distinguish raw source claims from fully initialized output;
clock wrappers separate wall time from generation-bound monotonic time.
Pending work owns partially initialized state before activation, retains
destruction obligations and fails closed on incomplete cleanup.

These interfaces do not supply OS randomness, a DRBG, a clock, external key
storage, certificate validation or CPU detection. A caller-provided destructor
receipt or self-test runner is an assertion, not independently established
evidence. Mandatory cleanup failure hooks must make failure durable or fail-stop.

FIPS-aware services are currently non-approved and effect-free.
`FipsModuleSession` failure is caller-session-local: independent sibling
sessions do not share a module-wide irreversible latch. Executable or approved
FIPS services must not be introduced before that planned stronger boundary.
Security events are bounded observations, never permission to execute or commit
a security decision.

## Hardware and SIMD

No cipher/hash acceleration or runtime CPU probing occurs here. The narrowly
reviewed volatile-clearing and compiler-barrier boundary supports higher-level
owners. ISA kernels live in the optional CPU crates, outside default consumers.

## Cleanup limits

Clearing covers source-declared owned Rust memory while execution continues.
Callers retain responsibility for original inputs, exposed bytes and copies.
Registers, compiler copies/spills, caches, DMA, dumps, swap, `mem::forget`,
abort, forced termination and power loss are not covered. The optional
`brynja-sanitization` adapter is not required for core-owned clearing.

[Memory policy](https://github.com/valkyoth/brynja/blob/main/docs/unsafe-policy.md)
· [Threat model](https://github.com/valkyoth/brynja/blob/main/docs/threat-model.md).
MIT OR Apache-2.0.
