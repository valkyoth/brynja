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

# brynja-mac-kmac

First-party, allocation-free `no_std` KMAC128/256 and KMACXOF128/256 from
NIST SP 800-185, built on Brynja's hardened cSHAKE owner.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| KMAC128/256 and KMACXOF128/256 | ✅ Fully implemented | ❌ No |
| Byte/bit input, opaque tags and typed secret XOF output | ✅ Implemented | ❌ No |
| Hardened accelerated execution | ✅ Opt-in, platform-limited | ❌ No |

All services report `NonApproved`. Project tests and pentests are not named
independent cryptographic review; Brynja has no FIPS 140-3 validation.

## Use

The current APIs are available from the unpublished workspace leaf:

```sh
cargo add brynja-mac-kmac --path /path/to/brynja/crates/brynja-mac-kmac --no-default-features
```

Authenticate a message with an application-provided secret key. The fixed
example key below is only test data, not a key-generation recipe.

```rust
use brynja_mac_kmac::Kmac128;
let key = [0x42; 32]; // Example only.
let mut mac = Kmac128::new(&key, b"example protocol").unwrap();
mac.update(b"authenticated message").unwrap();
let mut tag_bytes = [0; 32];
let tag = mac.finalize_tag(&mut tag_bytes).unwrap();
assert!(tag.verify_candidate(tag.as_bytes()).expose_public());
```

Keep derived output secret rather than implicitly converting it to public bytes:

```rust
use brynja_mac_kmac::KmacXof256;
let key = [0x42; 32]; // Example only.
let mut reader = KmacXof256::new(&key, b"example derivation").unwrap().finalize_xof().unwrap();
let mut destination = [0; 64];
{
    let secret = reader.squeeze_secret(&mut destination).unwrap();
    assert_eq!(secret.expose().len(), 64);
}
assert_eq!(destination, [0; 64]);
```

Production constructors enforce keys and fixed tags at least as long as the
selected security strength. Exact standards-valid weak/short parameters are
available only through explicit `conformance-testing` APIs; enabling them is
not permission to weaken a protocol. Callers must reject candidate/tag lengths
above their protocol's limit at ingestion: verification work depends on the
public candidate length.

## Hardware and SIMD

Defaults remain portable. `hardened-execution` exposes the separate
`execution` API; `runtime-execution` additionally enables hosted support.
Static x86-64 AVX2 and AArch64 SHA3/NEON operate through hardened Keccak.
Hosted selection requires qualifying AArch64 system-wide CPU authority.
Generic x86 hosted execution is unavailable; required requests fail closed.

No feature changes ordinary constructors or installs a global backend. Secret
owners cannot use non-erasing raw kernels, and a supplied backend error never
silently falls back. See the
[accelerated API and memory boundary](https://github.com/valkyoth/brynja/blob/main/docs/kmac-accelerated-execution.md).

## Secret ownership

Key-derived sponge, metadata, encodings and staging clear on success, errors,
cancellation, recoverable unwind and Drop. Fixed tags are opaque, without
ordinary equality or formatting. XOF output remains a secret owner unless
the caller explicitly declassifies it. A consumed composition owner cannot
reopen as another function.

Callers own original key/message buffers and copied outputs. Registers,
compiler copies/spills, caches, dumps, DMA, swap, forgotten owners, abort and
forced termination are outside the erasure guarantee. No platform-wide memory
locking or dump policy is imposed by this portable crate.

MIT OR Apache-2.0.
