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
| Hardware/SIMD selection and protected/resident sessions | Not implemented by this HMAC API | No |
| General SHA-512/t and arbitrary-bit profiles | Not implemented by this HMAC API | No |

No FIPS approval or certification is claimed. Ordinary hash state is never
used for keys or intermediate digests. Existing hash evidence does not qualify
this new composition. The algorithm interface is sealed, not blanket-implemented
for arbitrary digests or XOFs.

## Hardware and SIMD

This initial HMAC API is portable only. It does not select dedicated SHA
instructions or SIMD batches, even when another dependency enables a leaf's
acceleration features. Existing accelerated hashes are not automatically HMAC
qualification. Explicit accelerated and protected/resident HMAC composition
remains development work; no speedup or strict-memory claim is made here.

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
python3 scripts/hmac/check-hmac-package.py --no-std-target x86_64-unknown-none
```

The external-oracle test is intentionally ignored by ordinary Cargo runs and
executed explicitly by the second command; it must not be counted as a pass
when ignored. RFC vectors are from [RFC 4231](https://www.rfc-editor.org/rfc/rfc4231.html);
construction and key guidance follow [RFC 2104](https://www.rfc-editor.org/rfc/rfc2104.html).

Package acceptance executes all seven RFC cases in debug and release, rejects
67 API/ownership probes and seven compiled algorithm/comparison mutations, and
builds all ten algorithm consumers for the requested installed `no_std` target.
The private synthetic-hash fixture injects 132 errors/unwinds across construction,
update and finalization, checks owner destruction and in-lifetime scratch
clearing, and rejects four compiled lifecycle/policy mutations. Its synthetic
hash is never exported or shipped. These are composition tests, not evidence of
register erasure, hash-kernel cleanup, timing resistance or independent review.

The incremental verifier selects HMAC independently from unchanged hash families.
Eleven bounded Miri tasks cover the ten adapters and consumer unwinding; native
matrices retain their full coverage. The HMAC ASan runner forces leak detection
and fatal errors. Two Kani proofs cover only the actual public-length policy
predicates, not the cryptographic construction. These checks remain author-run
assurance, not independent qualification, and do not establish hardware or
protected-memory support.
