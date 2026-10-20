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

# brynja-mac-hmac

First-party, allocation-free `no_std` HMAC over sealed, secret-bearing SHA-2 and
SHA-3 owners. **Under development; not release-qualified or independently
reviewed.** This leaf is not yet exposed through the modern or strict facades.

## Cryptography Verification Status

| Capability | Implemented | Independently verified |
| --- | --- | --- |
| HMAC-SHA-224/256/384/512 and SHA-512/224, SHA-512/256 | Portable initial implementation | No |
| HMAC-SHA3-224/256/384/512 | Portable initial implementation | No |
| Streaming, long-key normalization, explicit byte truncation, verification | Initial implementation with author tests | No |
| Typed public/secret tags; owned-memory destruction | Implemented; HMAC-specific compiler qualification pending | No |
| Explicit static SHA-2/Keccak accelerated composition | Implemented behind `hardened-execution`; HMAC-specific qualification pending | No |
| Hosted detection, SIMD batching and protected/resident sessions | Not implemented by this HMAC API | No |
| Canonical final-bit messages for the ten named algorithms | Implemented with author differential and lifecycle tests | No |
| General SHA-512/t, t ≥ 128 and t < 512 except 384; exact full-bit tags | Portable implementation with author tests across 383 parameters | No |
| General SHA-512/t below 128 bits | Rejected by HMAC's minimum-tag policy | Not an enabled profile |
| Fractional keys and arbitrary bit-level truncation | Not implemented by this HMAC API | No |

No FIPS approval or certification is claimed. Ordinary hash state is never
used for keys or intermediate digests. Existing hash evidence does not qualify
this new composition. The algorithm interface is sealed, not blanket-implemented
for arbitrary digests or XOFs.

## Hardware and SIMD

The default `Hmac` remains portable even when another dependency enables hash
acceleration. The opt-in `execution::Hmac` borrows an explicit static CPU
`execution::Authority`: use `from_static(&authority, key)` or
`from_static_with_tag_length(&authority, key, bytes)`. It supports the same ten
named identities and general SHA-512/t, and returns the same typed tags.
All normalization/inner/outer states use hardened hash execution, never ordinary
public-data hash owners. No error authorizes fallback.

The `hardened-execution` Cargo feature alone does not enable instructions.
Build-wide target features must match the selected kernel; the deployment must
guarantee both CPU instructions and OS register-state support throughout the
authority's lifetime. This static API does not detect features, pin threads or
make VM migration safe. Use portable HMAC when that guarantee cannot be made.
Backend failure or recoverable unwinding drops both HMAC hash owners and makes
the stream terminal. Only atomic SHA-2 length rejection preserves a stream;
SHA-3 overflow is terminal because its hash owner has already been cleared.

Author tests have exercised x86 SHA-224/256 and AVX2 Keccak composition locally.
Dedicated SHA-512 and Arm execution remain pending; cross-compilation alone is
not native qualification. Hosted detection, SIMD batching and protected/resident
HMAC remain development work. No performance or protected-memory claim is made.

## API examples

Use the unpublished workspace leaf while development is in progress:

```sh
cargo add brynja-mac-hmac --path /path/to/brynja/crates/brynja-mac-hmac --no-default-features
```

```rust
use brynja_mac_hmac::{Hmac, Sha256};
let key = [0x42; 32]; // Example only; generate real keys securely.
let mut mac = Hmac::<Sha256>::new(&key)?;
mac.update(b"authenticated message")?;
let mut bytes = [0; 32];
let tag = mac.finalize_tag(&mut bytes)?;
let mut verifier = Hmac::<Sha256>::new(&key)?;
verifier.update(b"authenticated message")?;
assert!(verifier.verify(tag.as_bytes())?.expose_public());
# Ok::<(), brynja_mac_hmac::Error>(())
```

`Hmac::<Sha256>::authenticate(key, message, destination)` is the full-tag
one-shot equivalent. For a protocol-defined truncated tag, both endpoints must
select the exact length with `with_tag_length(key, length)` **before** processing
the message. Never derive that policy from an attacker-supplied tag's length.
This initial API accepts 16 through the full digest size in bytes. Shorter tags
reduce guessing resistance; applications own key-use and verification budgets.

Use `finalize_secret` to retain the output as secret material: its typed owner
clears the caller destination on drop. Public tag errors leave the destination
unchanged; secret-output errors clear it. States have no cloning, reset,
formatting or cross-thread transfer API.

For a message ending in a partial byte, use `authenticate_bits`, or finish a
byte-streaming prefix with `finalize_bits_tag`, `finalize_bits_secret` or
`verify_bits`. SHA-2 takes `Sha2BitString` (valid high bits); SHA-3 takes
`Fips202BitString` (valid low bits). Their constructors reject nonzero unused
bits, and the types cannot be interchanged. Finalization consumes the stream.
Keys and tag-length selection remain byte-based; this is not fractional-key or
arbitrary bit-level truncation support.

`Hmac::<Sha512T<129>>::new(key)` selects a full 129-bit tag stored in 17 bytes.
Both tag owners expose `bit_len()`; unused low bits of the last byte are zero
and verification compares them rather than accepting noncanonical encodings.
`with_tag_length(key, 16)` selects its 128-bit prefix, but 17-byte truncation
is rejected because it exceeds 129 bits. General parameters below 128, 384,
zero and values at least 512 are rejected. The general /224 and /256 identities
are distinct Rust types from the named variants, with matching mathematical
outputs. General parameter support is not FIPS approval.

All key lengths, including zero, are mathematically accepted. Empty or
predictable keys are insecure; the API cannot measure entropy. Applications must
supply suitable independently generated keys. Caller-owned buffers and copies,
compiler-created moves/spills, paging, fatal aborts and OS snapshots remain
outside the owned-memory guarantee. This is not a protected-memory API.

## Package contents and testing

The crates.io allowlist contains runtime Rust sources, Cargo metadata, this
README and both licences. Tests, oracle scripts and assurance evidence remain
in the Git repository; no captures or evidence archives belong in the crate.

```sh
cargo test -p brynja-mac-hmac --locked --offline
python3 scripts/hmac/check-hmac-differential.py
python3 scripts/hmac/check-hmac-bit-differential.py
python3 scripts/hmac/check-hmac-general-differential.py
python3 scripts/hmac/check-hmac-package.py --no-std-target x86_64-unknown-none
```

The three external-oracle tests are intentionally ignored by ordinary Cargo runs
and executed explicitly by their corresponding scripts; ignored tests must not
be counted as passes. The byte campaign has 1,100 Python/OpenSSL cases; the
bit campaign has 1,040 cases using the separate repository Python SHA-2/SHA-3
models, with byte-aligned controls checked against Python/OpenSSL. These are
author-generated differential cases, not official bit vectors or independent
qualification. The general SHA-512/t campaign adds 6,128 cases across all 383
admitted parameters, preserving the exact inner digest bit length at the outer
hash boundary. Its Python model derives its SHA-512 constants independently,
with named /224 and /256 OpenSSL controls.
RFC vectors are from [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html);
construction and key guidance follow [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html).

Package acceptance executes all seven RFC cases in debug and release, rejects
118 portable API/ownership probes and eleven compiled algorithm/comparison mutations, and
builds twelve algorithm consumers (ten named plus two general bit widths) for
the requested installed `no_std` target.
The private synthetic-hash fixture injects 328 errors/unwinds across construction,
update and finalization, checks owner destruction and in-lifetime scratch
clearing, and rejects four compiled lifecycle/policy mutations. Its synthetic
hash is never exported or shipped. These are composition tests, not evidence of
register erasure, hash-kernel cleanup, timing resistance or independent review.
The extracted accelerated API additionally compiles twelve positive identities
and rejects 66 ownership, authority-lifetime and API misuse probes. Four retained
owner lifecycle tests and four compiled mutations cover backend failure,
unwinding, atomic length rejection and SHA-3's terminal overflow mapping.
These generic lifecycle tests do not execute CPU instructions.

Native route tests are explicitly ignored in generic runs. On a deployment
known to support SHA-NI, SSE2, AVX and AVX2, execute the narrow SHA-2 and Keccak
routes with:

```sh
RUSTFLAGS='-C target-feature=+sha,+sse2,+avx,+avx2' cargo test -p brynja-mac-hmac \
  --features hardened-execution --test execution --release -- --ignored --skip native_sha512
```

The separate `native_sha512` case requires dedicated SHA-512 instructions
(or explicitly identified emulation), not merely AVX-512 support. Do not run it
on unsupported hardware. Arm routes require their matching complete target
features and a separate native run.

The incremental verifier selects HMAC independently from unchanged hash families.
Fourteen bounded Miri tasks cover the ten named adapters, two general widths,
consumer unwinding and the instruction-free execution-owner lifecycle; native
matrices retain their full coverage. The HMAC ASan runner forces leak detection
and fatal errors. Two Kani proofs cover only the actual public-length policy
predicates, not the cryptographic construction. These checks remain author-run
assurance, not independent qualification, and do not establish hardware or
protected-memory support.
