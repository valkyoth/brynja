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
| Hosted SHA-1 hardware sessions | Explicit protected/resident owners, worker-local authority and terminal quarantine | ❌ No |
| Protected/resident MD5 SIMD batches | Explicit bounded owners; full groups, aggregate verification and clearing output loans | ❌ No |
| Apple Silicon resident profile | Scalar SHA-1/MD5 sessions; native lifecycle/bit tests; no dump exclusion | ❌ No |

## Hardware and SIMD

The generic `Session<A>` always uses portable hardened hashes on the selected
protected/resident worker, even when Cargo unifies acceleration features.
Separate `Sha1CompiledSession` owners require `strict-sha1-acceleration` on
Linux or `macos-resident-sha1-acceleration` on Apple Silicon. They use SHA-NI
on x86-64 or SHA-1 instructions on AArch64, not multibuffer SIMD. The Cargo
feature alone is insufficient: build-wide `+sha,+sse2` or `+neon,+sha2`
must match CPU/OS support throughout deployment. There is no runtime detection,
scheduler lock or live-migration guarantee. Establish that contract before
construction; unsupported configurations return errors, not scalar fallback.
Separate `Md5BatchSession` owners require `strict-md5-batch` on Linux or
`macos-resident-md5-batch` on Apple Silicon. Their build-wide features are
`+avx2` (including OS YMM support) or `+neon`, under the same explicit
deployment contract. These are independent-message SIMD kernels, not dedicated
MD5 instructions. The distinct macOS resident profile never
substitutes for Linux strict execution. No register-erasure or whole-process
protection claim is made.

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

For Apple Silicon, select `macos-resident` explicitly instead. Its session and
output types are distinct from `strict_execution`, even if both features are
enabled. The profile has guarded, locked, fork-excluded memory but **no core-dump
exclusion**. Applications requiring dump exclusion must not substitute it.

```rust
# #[cfg(feature = "macos-resident")]
fn resident_legacy_request() -> Result<(), brynja_legacy_hmac_std::macos_resident::Error> {
    use brynja_legacy_hmac_std::macos_resident::*;
    let mut session = Session::<Md5>::new(LegacyUse::acknowledge(), TagPolicy::Bytes(12), Limits {
        stack_bytes: 262144, max_stack_mapping_bytes: 1048576,
        max_buffer_mapping_bytes: 65536, max_key_bytes: 4096,
        max_message_bits: 65536, max_chunks: 16,
    })?;
    let tag = session.authenticate(&[0x42; 32], b"legacy message")?;
    assert_eq!(tag.expose().len(), 12);
    drop(tag);
    Ok(())
}
```

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

## Explicit SHA-1 hardware owner

Enable the separate acceleration feature and deploy a matching build as above.
The constructor probes the selected authority on the protected/resident stack
before accepting any key. Every request reconstructs that exact backend there.

```rust
# #[cfg(feature = "strict-sha1-acceleration")]
fn hardware_request(
    limits: brynja_legacy_hmac_std::strict_execution::Limits,
) -> Result<(), brynja_legacy_hmac_std::strict_execution::Error> {
    use brynja_legacy_hmac_std::strict_execution::*;
    let mut session = Sha1CompiledSession::new(
        LegacyUse::acknowledge(), TagPolicy::Full, limits,
    )?;
    let tag = session.authenticate(&[0x42; 32], b"legacy message")?;
    assert_eq!(tag.expose().len(), 20);
    drop(tag);
    Ok(())
}
```

The resident module exposes the same method names on distinct types; it does
not acquire Linux dump-exclusion guarantees. Backend/invariant failures and
recoverable worker unwinds permanently quarantine either compiled session.
Cancellation, tag mismatch, malformed requests and pre-entry thread-setup errors
preserve reuse. No error authorizes switching to the scalar session. Quarantine
also clears retained output, including a forgotten loan.

## Explicit MD5 SIMD batch owner

Select the separate MD5 feature above and a tag policy before providing keys.
A batch needs at least one complete aligned group: all eight slots for AVX2,
or slots 0–3 or 4–7 for NEON. No dummy lanes are inserted. Ineligible batches
reject without falling back. Key/message lengths, active slots and compression
budgets are public; externally pad them if those dimensions are confidential.

```rust
# #[cfg(feature = "strict-md5-batch")]
fn legacy_batch(
    limits: brynja_legacy_hmac_std::strict_execution::Md5BatchLimits,
) -> Result<(), brynja_legacy_hmac_std::strict_execution::Error> {
    use brynja_legacy_hmac_std::strict_execution::*;
    let mut session = Md5BatchSession::new(
        LegacyUse::acknowledge(), TagPolicy::Bytes(12), limits,
    )?;
    let inputs = core::array::from_fn(|_| Some(Md5BatchInput {
        key: b"example-only key, replace in applications",
        message: Bits::bytes(b"legacy message"),
    }));
    let tags = session.compute(&inputs, &Cancellation::new())?;
    assert_eq!(tags.expose(0).map(<[u8]>::len), Some(12));
    drop(tags); // clears all 128 output bytes, not just active tag prefixes
    Ok(())
}
```

Each request receives one shared `max_compressions` budget across long-key,
inner and outer processing, including padding and all active lanes. Work limits
and cancellation preserve reuse; authority, internal and unwind failures
quarantine. `verify` requires exact active-slot/width agreement and releases
only one aggregate decision. Empty messages remain active when wrapped in
`Some`; `None` is inactive.

The existing hardened leaf selects scalar normalization for long keys without
a full SIMD group and scalar processing for unequal suffixes/padding. This is
public-shape selection before work, not an error fallback. Both ipad and opad
passes must report actual full-width SIMD work. All these paths run on the
protected/resident worker. The resident variant still has **no dump exclusion**.

