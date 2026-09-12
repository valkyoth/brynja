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

# brynja-test-support

Permanently unpublished, repository-only `no_std` fixtures. These predictable
helpers must never enter production dependency graphs.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| RFC 9850 diagnostic key-log encoder | ✅ Test-only | ❌ No |
| Deterministic fault-injecting random engine | ✅ Test-only | ❌ No |
| Scripted wall and monotonic clocks | ✅ Test-only | ❌ No |
| Production randomness, clocks or secure protocols | ❌ Not provided | Not applicable |

Fixture success is not independent cryptographic verification or certification.

## Repository use

```sh
cargo test --locked -p brynja-test-support
```

Random fixtures exercise retry, failure, partial writes, underfill, reseed and
destruction. Clock fixtures exercise unavailable observations, exhaustion and
rollback. Never use deterministic fixtures for real keys, nonces or security
deadlines.

The key-log encoder covers pinned IANA labels and LF/CRLF/CR endings. It
preflights complete output and preserves buffers on rejection. Key logging
discloses traffic secrets by design; the helper is prohibited from every
production package and feature, regardless of whether logging is enabled.

## Hardware and SIMD

None. This package supplies predictable test inputs and fault behavior, not a
crypto backend or performance implementation. It depends only on
`brynja-core` and remains `publish = false`.

MIT OR Apache-2.0.
