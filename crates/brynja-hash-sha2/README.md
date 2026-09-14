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

# brynja-hash-sha2

First-party, allocation-free `no_std` SHA-2: SHA-224, SHA-256, SHA-384,
SHA-512, SHA-512/224 and SHA-512/256, plus optional general SHA-512/t.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| Independent-message SHA-224/256 AVX2 / NEON batching | 🚧 Implemented; qualification pending | ❌ No |
| SHA-2 (all six identities, ordinary and hardened byte and arbitrary-bit APIs) | ✅ Fully implemented | ❌ Not independently verified |
| General SHA-512/t, all 510 valid parameters | ✅ Fully implemented; opt-in | ❌ No |
| Ordinary and hardened CPU execution | ✅ Opt-in, platform-limited | ❌ No |

These implementations follow FIPS 180-4. That algorithm standard is not
FIPS 140-3 validation: Brynja has no validated module or named independent
cryptographic review.

## Use

For bounded public-data batching, enable `batch-execution`. AVX2 handles eight
independent messages and NEON four; mixed SHA-224/256 identities, inactive slots
and unequal bit lengths retain their order. Output commits atomically. Ordinary
SIMD is not zeroizing and must not receive confidential input. Example portable
batch (the same shape is accepted by a session-backed executor):

```rust
use brynja_hash_sha2::{BitString, batch::{Algorithm, Control, Executor, Input, PublicData}};
let bits = BitString::new(b"abc", 8).map_err(|e| format!("{e:?}"))?;
let mut inputs = [None; 8];
inputs[0] = Some(Input::new(Algorithm::Sha224, bits));
inputs[1] = Some(Input::new(Algorithm::Sha256, bits));
let mut output = [None; 8];
let mut cancelled = || false;
let mut control = Control::new(2, &mut cancelled);
let report = Executor::portable().digest(PublicData::new(&inputs), &mut output, &mut control)
    .map_err(|e| format!("{e:?}"))?;
assert_eq!(report.scalar_blocks, 2);
assert_eq!(report.vector_calls, 0);
assert!(output[0].is_some() && output[1].is_some() && output[2].is_none());
# Ok::<(), String>(())
```

For explicit target/platform authority and workload thresholds, see the
[batch execution contract](https://github.com/valkyoth/brynja/blob/main/docs/sha256-batch-execution.md).

On x86-64, enabling the Cargo feature alone does not activate AVX2. Build the
application with `RUSTFLAGS="-C target-feature=+avx,+avx2"` only when every CPU
on which it may run supports that bundle and OS-enabled YMM state. A generic
x86-64 build stays portable in hosted `Mode::Prefer` and returns `Unavailable`
in hosted `Mode::Require`, even on an AVX2-capable machine. This is deliberate;
current-core CPUID alone does not prove safety across migration.

The APIs documented here include unpublished workspace functionality. From a
local checkout, without maintaining a dependency version in this example:

```sh
cargo add brynja-hash-sha2 --path /path/to/brynja/crates/brynja-hash-sha2 --no-default-features
```

Hash public bytes in one call or incrementally:

```rust
use brynja_hash_sha2::{Sha256, sha256};
let expected = sha256(b"abc").unwrap();
let mut hash = Sha256::new();
hash.update(b"a").unwrap();
hash.update(b"bc").unwrap();
assert_eq!(hash.finalize(), expected);
```

Arbitrary-bit input uses the high bits of the final byte; unused low bits must
be zero. Streaming accepts complete bytes until consuming `finalize_bits`.

```rust
use brynja_hash_sha2::{BitString, sha256_bits};
let bits = BitString::new(&[0b0110_0000], 3).unwrap();
assert_eq!(&sha256_bits(bits).unwrap().as_bytes()[..4], &[0x1f, 0x77, 0x94, 0xd4]);
```

Use a hardened owner when input or output is confidential:

```rust
use brynja_hash_sha2::HardenedSha256;
let mut destination = [0; 32];
{
    let mut hash = HardenedSha256::new();
    hash.update(b"confidential input").unwrap();
    let secret = hash.finalize_secret(&mut destination).unwrap();
    assert_eq!(secret.expose().len(), 32);
}
assert_eq!(destination, [0; 32]);
```

Enable `general-sha512-t` for `Sha512TBits`, `Sha512T`,
`HardenedSha512T` and their byte/bit one-shot APIs. Valid t values are
1..=511 excluding 384; small t provides correspondingly weak security.
Parameters remain part of digest identity. `Sha512TDigest::from_bytes`
imports an already public digest, not a message or secret; hardened paths
return secret owners, never implicitly pass through that public importer.
See the [general-t API contract](https://github.com/valkyoth/brynja/blob/main/docs/sha512-t-contract.md).

## Hardware and SIMD

Defaults remain portable and do not probe the CPU.

| Feature | Reachable API | Supported execution |
| --- | --- | --- |
| `batch-execution` | `batch`, public data only | Eight independent SHA-224/256 lanes with AVX2; four with AArch64 NEON |
| `static-execution` | `execution`, public data only | x86-64 SHA instructions for SHA-224/256; AArch64 SHA2/SHA-512 |
| `runtime-execution` | `execution` with hosted authority | Qualifying AArch64 system-wide feature guarantees |
| `hardened-execution` | Separate erasing execution owners | Static routes above; hosted routes with `runtime-execution` |
| `cpu` | Historical candidate sessions | Unadmitted; not an operational acceleration route |

x86-64 SHA-512 is portable; no separate multi-message SHA-512-family
backend is provided yet. SHA-224/256 multibuffer SIMD is the separate
`batch-execution` profile above. RISC-V Zknh candidates are QEMU/codegen-tested, not
enabled for production execution. Static binaries require compatible CPUs and
OS state throughout scheduling and migration. A current-core feature probe
alone is not sufficient hosted authority.

See [ordinary execution](https://github.com/valkyoth/brynja/blob/main/docs/sha2-ordinary-execution.md)
and [hardened execution](https://github.com/valkyoth/brynja/blob/main/docs/sha2-hardened-execution.md)
for authority construction, exact features, route reports and failure handling.

## Security boundaries

Ordinary states do not zeroize private state and must not process secrets.
Hardened owners clear source-declared state, buffers, schedules and scratch;
typed secret destinations clear on failure and Drop. Public output requires
explicit declassification. That acknowledgment records caller intent, not
access control.

Callers own input/output copies and ingestion work limits. Cleanup does not
guarantee erasure of registers, compiler copies/spills, caches, dumps, swap,
forgotten owners, aborts or forced termination. A raw hash or ordinary digest
equality is not authentication, MAC verification or password hashing.

[Verification inventory](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md).
MIT OR Apache-2.0.
