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

# brynja-legacy-hmac-std

Explicit hosted legacy HMAC-SHA-1 and HMAC-MD5. Do not use these algorithms
for new protocols. No modern facade, default negotiation or approved service
selects this package. Install explicitly with `cargo add brynja-legacy-hmac-std`
once published; until then use the reviewed workspace path.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Protected scalar SHA-1/MD5 HMAC | Linux-only `strict-execution`; byte/chunk/bit and tag-policy author tests pass | ❌ No |
| Protected output loans and worker clearing | Native mapping/fault checks and extracted debug/release mutation tests pass | ❌ No |
| Protected accelerated SHA-1/MD5 batches | Pending | ❌ No |
| Apple Silicon resident profile | Pending; not a Linux strict fallback | ❌ No |

## Hardware and SIMD

These sessions use portable hardened hash implementations on protected workers.
Dependency feature unification never enables acceleration here. Separate
accelerated sessions and the explicitly weaker macOS resident profile remain
pending. No register-erasure or whole-process protection claim is made.

## API use

Enable `strict-execution` explicitly. Construction preacquires a guarded,
locked, dump/fork-excluded worker stack and separate staging/output mappings on
native GNU/Linux x86-64 or little-endian AArch64. Unsupported targets and resource
failures return errors with no ordinary-memory fallback.

```rust
# #[cfg(feature = "strict-execution")]
fn legacy_request() -> Result<(), brynja_legacy_hmac_std::strict_execution::Error> {
    use brynja_legacy_hmac_std::strict_execution::*;
    let mut session = Session::<Sha1>::new(LegacyUse::acknowledge(), TagPolicy::Full, Limits {
        stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 65536, max_key_bytes: 4096,
        max_message_bits: 65536, max_chunks: 16,
    })?;
    let output = session.authenticate(&[0x42; 32], b"legacy message")?;
    assert_eq!(output.expose().len(), 20);
    drop(output); // clears the session-owned output mapping
    Ok(())
}
```

`compute` accepts ordered chunks and a canonical MSB-first bit tail. `verify`
releases only a boolean. Select tag width before processing; byte truncations
range from ten bytes to the full digest width. Candidate lengths never select
policy. Empty or predictable keys are mathematically accepted but insecure.

All keyed state is created and consumed on the joined worker. No application
callback or secret-bearing thread return is exposed. Output errors clear staging
and output; forgetting a loan cannot disable clearing on session reuse/Drop.
Key setup is bounded, not internally cancellable; updates check cancellation at
4096-byte boundaries. A cancellation racing after the final check may complete.

Caller inputs/copies, compiler registers, TLS/panic hooks, snapshots, hibernation,
privileged inspection and fatal termination are outside the protection boundary.
Deployment must prohibit fork, native thread cancellation and external protection
revocation while resources are live. Stack sizes are not stack-depth proofs.
This package is not independently qualified, FIPS approved or certified.

