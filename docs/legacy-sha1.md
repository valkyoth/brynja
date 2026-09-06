# Legacy SHA-1 implementation and assurance

v0.24.18 implements the complete portable SHA-1 primitive in the separate
`brynja-legacy-sha1` leaf. Final family acceptance remains v0.24.20–v0.24.23;
acceleration is not implemented here. The family remains **In progress**.

## Normative boundary

[FIPS 180-4](https://doi.org/10.6028/NIST.FIPS.180-4) §§4.1.1, 4.2.1,
5.1.1, 5.2.1, 5.3.1 and 6.1.2 govern the functions, constants, MSB-first
padding, big-endian length, IV, 80-round schedule and 160-bit digest. The
alternative memory schedule in §6.1.3 computes the same function and does
not require a separate public algorithm. Input is strictly shorter than 2^64
bits; final non-byte-aligned tails are canonical and consuming.

The standard's name does not establish FIPS 140-3 module validation. SHA-1's
broken collision resistance prohibits treating these APIs as modern security
defaults. No modern facade, generic-hash router, TLS, PKIX or FIPS policy
selects this leaf. Dependencies point only to generic first-party ownership
and bit-string foundations, never from modern crypto back into legacy code.
Future HMAC, HKDF and OpenPGP users must obtain separately typed protocol/
construction admission; they must not reimplement SHA-1 or infer admission
from the presence of this package or its hardened marker.

## Public API and lifecycle

Ordinary: `Sha1::{new,update,finalize,finalize_bits,message_bits,
check_additional_bytes,check_additional_bits}`, `sha1`, `sha1_bits`.
Hardened: `HardenedSha1` supports byte streaming, consuming public/secret
finalization with or without a bit tail, capacity probes, and secret one-shot
byte/bit calls. Public release requires `PublicDeclassification`; secret
release yields an affine `OwnedSecretRegion`. No Clone, Debug, reset,
serialization, state import/export, public compression, or CPU backend API.
These omissions prevent secret duplication and unvalidated state injection;
they are not missing SHA-1 operations.

Updates admit length before mutation. Consuming finalization rejects exhausted
input before writing public output; secret failures clear the full destination.
Private storage comprises six fixed byte regions: chaining state, block and
padding, schedule, bit length, buffered count, output staging. Both ordinary
and hardened APIs own the same clearing implementation. Hardened capability
is sealed and cannot be asserted by downstream code. Clearing cannot depend
on an optional feature or the external sanitization adapter.

Source-owned regions clear on Drop through `brynja_core::clear_owned_region`;
compression clears its block, schedule and buffered count between blocks.
Recoverable unwind and early cancellation run the same non-panicking Drop.
Private update/padding offset guards are always-on in debug and release; an
invalid offset panics before writing instead of silently dropping input. Safe
public APIs cannot create this state. The consuming application's panic
strategy controls unwind versus abort; our repository profile does not force
downstream settings. See [panic strategy](panic-strategy.md).
Update errors retain unchanged live state until the caller drops or retries.
No physical-copy, register, compiler spill/copy, cache, DMA, locked-memory,
swap, dump, abort, termination, forget, or caller-copy erasure is promised.
Scalar round words and length conversion temporaries have residual compiler/
register copy risk, not an assertion of complete machine-state erasure.

## Reproducible conformance

Official data comes from [NIST CAVP secure hashing](https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/secure-hashing):
`shabittestvectors.zip`, SHA-256
`cd7b9f11680c6e0ccdbe13b28403f2017b5ff48789152162461e0a24fb4c5d45`.
The checked-in text selects all 513 SHA1ShortMsg cases and the first 16
SHA1LongMsg cases. Only unused storage bits are canonicalized; message bits
and expected digests are unmodified. Empty placeholder `00` becomes `-`.
NIST US-government test data is retained; the archive stays local under `/tmp`
or a gitignored reference directory. `import-nist-vectors.py ARCHIVE` verifies
the archive hash and reproduces/checks the selection. These examples do not
replace CAVP validation.

Run from the root:

```sh
cargo test --locked -p brynja-legacy-sha1
cargo test --locked --manifest-path assurance/sha1-public-api/Cargo.toml
python3 scripts/sha1/check-sha1-differential.py
python3 scripts/sha1/check-sha1.py
python3 scripts/sha1/test-sha1.py
scripts/sha1/check-sha1-codegen.sh 1.90.0
scripts/sha1/check-sha1-codegen.sh 1.98.1
scripts/zeroization/check-zeroization-miri.sh --group sha1
```

The differential adapter caps input records and output, rejects malformed
width/length/hex requests before crypto execution, and has no registry
dependencies. A separate Python bit oracle checks 1,135 deterministic cases;
byte-aligned results are also checked with Python's hashlib SHA-1. Python/
OpenSSL is test-only and never implements production Brynja cryptography.
Miri covers owner/length tests, padding/tail boundaries, failure and unwind;
million-byte and exhaustive vector repetition run in ordinary tests/ASan,
not the interpreted Miri profile. Kani proves the full u64 length-admission
domain on its separate 1.90.0 verifier toolchain. Emitted-code checks cover
owned region clearing, not speculative, register or whole-machine erasure.

No external crate was added. No native evidence is needed for this portable
milestone. New crypto and secret ownership require an exceptional pentest
before an internal tag; no publication is selected at v0.24.18.
