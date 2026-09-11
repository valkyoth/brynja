# Ordinary cSHAKE and hosted sponge execution

The v0.24.36 candidate adds `execution::{Cshake128, Cshake256}` to
`brynja-hash-sha3`, using its default-off `static-execution` and
`runtime-execution` features. Portable default constructors are unchanged.
All input, function-name (`N`) and customization (`S`) data must be explicitly
classified `Public` or `PublicBits`. This is a caller assertion, not automatic
secrecy detection. These ordinary owners and their scratch are non-erasing;
never use them for KMAC, password hashing, key derivation or confidential input.
Use the separate existing portable hardened owners for secret-bearing work.

## Complete cSHAKE surface

Both strengths expose `new`/`new_bits`, `update`, consuming
`finalize_xof`/`finalize_bits_xof`, and byte/bit one-shot
`hash_with_scratch`/`hash_bits_with_scratch`. Readers expose incremental
`squeeze`/`squeeze_with_scratch`, consuming final-bit output, byte/bit preflight
checks, successful complete-byte counts and immutable execution reports.
All errors are typed; failed finalization consumes its state.

The implementation follows [NIST SP 800-185 §3](https://csrc.nist.gov/pubs/sp/800/185/final):
empty N/S is exactly SHAKE; otherwise the prefix is
`bytepad(encode_string(N) || encode_string(S), rate)` with the cSHAKE domain.
Arbitrary-bit X/N/S use canonical FIPS 202 low-bit-first representation.
Every prefix, message, padding and squeeze permutation uses the retained route.
No backend error, including a prefix failure, authorizes a scalar retry.
Captured backend errors retain their identity. An otherwise unclassified shared
prefix-encoding failure is `Error::PrefixEncoding`, not a guessed length overflow.

`setup_bytes` reports encoded prefix capacity; `message_bytes` excludes it.
`Report::absorb_permutations` includes prefix permutations. Byte/bit preflights
include setup capacity and round partial backing bytes upward. Reports are
observations, not independent verification, FIPS validation or execution permits.

Updates preserve the retained state on failure. Readers stage each output into
caller scratch before committing output/state; errors preserve the destination
and reader even after a late permutation failure. Scratch may change on failure.
The convenience methods support up to 168 bytes per request; arbitrary-sized
transactions use caller scratch at least as long as the destination. No heap
allocation, unsafe code, new kernel, global installation or hidden fallback is added.

```rust
use brynja_hash_sha3::execution::{Cshake128, Execution, Public};
let mut state = Cshake128::new(
    Execution::portable(), Public::new(b""), Public::new(b"Email Signature"),
)?;
state.update(Public::new(&[0, 1, 2, 3]))?;
let mut reader = state.finalize_xof()?;
let mut output = [0; 32];
reader.squeeze(&mut output)?;
```

For specialized binaries, borrow `Execution` from `StaticSelection` as in the
[SHA-3/SHAKE execution guide](sha3-ordinary-execution.md). Target flags must be
valid on every CPU on which the binary can execute, not just the build machine.

## Hosted adapters

Enable `sponge-execution` on **brynja-crypto-cpu-std**, not on the facade.
The optional first-party SHA-3 dependency points downstream from this hosted
adapter; it introduces no `std` dependency into the hash leaf or default graph.

```rust
use brynja_crypto_cpu_std::sponge::{Mode, Public, Sponge};
let owner = Sponge::new(Mode::Prefer)?;
let selection = owner.report(); // includes any portable-fallback reason
let mut state = owner.cshake256(Public::new(b""), Public::new(b"my protocol"))?;
state.update(Public::new(b"public message"))?;
let mut reader = state.finalize_xof()?;
reader.squeeze(&mut [0; 64])?;
```

`Sponge` also constructs all four SHA-3 hashes and both SHAKE strengths, and
provides `cshake128_bits`/`cshake256_bits` for arbitrary-bit N/S. Borrowed
`execution()` supports one-shot calls without duplicating API implementations.
Owners and streams are neither Send nor Sync; borrowed streams cannot outlive
their authority. Quarantine invalidates accelerated readers, including empty reads.
Portable selections have no hardware owner to quarantine.

`Portable` never probes. `Prefer` falls back only for pre-execution unavailability
and reports the reason. `Require` rejects unavailable guarantees. Current hosted
AArch64 authorization uses supported OS feature contracts; generic x86/unknown
platforms do not gain migration guarantees merely because CPU flags are present.
The [hosted execution contract](hosted-cpu-execution.md) remains normative.

## Verification and release boundary

The packaged consumer runs 628 cSHAKE cases (four official NIST examples and
624 independently generated bit-oracle cases), with one-shot, streaming,
incremental output, exact setup counts and byte/bit comparisons. The existing
1,084 SHA-3/SHAKE cases remain in the same consumer. Reproduce with:

`cargo run --locked --offline --release --manifest-path assurance/sha3-execution/Cargo.toml -- portable`

Modes are `portable`, `prefer`, `static`, `hosted`. Required static mode needs
matching target features and actual hardware. Compiled negative/mutation tests
cover input classification, ownership, prefix errors, lost routing and scalar
substitution. Supplemental QEMU cannot substitute for native observations.

The owner-supplied exceptional pentest/retest passed; fresh native cSHAKE/hosted
collection remains a release prerequisite. Adding the optional hosted dependency changes that
package's build closure, so the existing strict SHA-2 hardened native gate also
requires a refreshed collection; its previous artifacts are not rewritten.
No independent cryptographic review, side-channel certification, migration
qualification, FIPS validation or secret-erasure guarantee is claimed.
