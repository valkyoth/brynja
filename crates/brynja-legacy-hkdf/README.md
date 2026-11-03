# brynja-legacy-hkdf

Explicit, allocation-free `no_std` RFC 5869 HKDF-SHA-1 compatibility for
historical protocols. Do not use this crate for new protocols. It is separate
from the modern Brynja facade and requires `LegacyUse::acknowledge()` when
extracting or importing a pseudorandom key (PRK).

`Sha1Prk` supports Extract, imported PRKs, Expand and multipart `expand_parts`.
Multipart info is plain concatenation: it adds no framing or domain separation.
Callers must encode unambiguous protocol context themselves. Expansion is
limited to 255 SHA-1 blocks (5100 bytes). There is no MD5 HKDF, TLS key schedule,
TLS label helper or modern algorithm fallback.

PRK and output owners borrow caller-provided storage and clear it on ordinary
drop and recoverable unwind. Caller-created copies, forgotten owners, compiler
spills, registers, paging, crash dumps and aborts are outside that guarantee.
Applications must bound attacker-controlled input lengths and multipart part
counts; this API does not impose a processing-work quota. HKDF is not password
hashing and cannot create entropy absent from its input.

## Verification and deployment

Project tests are not independent cryptographic certification or deployment
approval. HKDF-specific independent review and target/compiler side-channel
qualification remain separate requirements. See the repository's
[verification status](https://github.com/valkyoth/brynja/blob/main/docs/VERIFICATION_STATUS.md)
and [public API assurance notes](https://github.com/valkyoth/brynja/blob/main/docs/assurance/hkdf-public-api.md).

## License

Licensed under either the Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
or the MIT license ([LICENSE-MIT](LICENSE-MIT)), at your option.
