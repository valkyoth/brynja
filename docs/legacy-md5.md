# Legacy MD5 implementation and assurance

v0.24.19 implements portable MD5 in the isolated `brynja-legacy-md5` leaf.
Final family acceptance remains v0.24.20–v0.24.23. The family remains
**In progress**; this milestone supplies no SIMD or CPU admission.

## Normative boundary

[RFC 1321](https://www.rfc-editor.org/rfc/rfc1321.html) §§2–3 defines
arbitrary-bit messages, MSB-first partial bytes, little-endian words, the
four 16-step rounds, IV, padding and 128-bit digest. The padding length is
the low 64 bits even when a message exceeds 2^64 bits. This API uses checked
u128 accounting and rejects larger representable requests before mutation;
that explicit API cap is not a SHA-1/FIPS length bound. Injected counter tests
check crossing 2^64 and equivalent low-64 padding without enormous inputs.

[RFC 6151](https://www.rfc-editor.org/rfc/rfc6151.html) is the security update.
MD5 is collision- and chosen-prefix-broken. Do not use it for new security
designs, signatures, certificates, password hashing or authentication. A raw
digest is not a MAC. Clearing memory does not repair MD5. No modern facade,
generic-hash default, TLS, PKIX or FIPS selection includes this leaf. Later
legacy HMAC/protocol use requires separate typed admission.

## Public API and lifecycle

Ordinary: `Md5::{new,update,finalize,finalize_bits,message_bits,
check_additional_bytes,check_additional_bits}`, `md5`, `md5_bits`.
Hardened: `HardenedMd5` provides byte streaming, consuming byte/bit finalization,
capacity probes and secret one-shot byte/bit calls. Public output requires
`PublicDeclassification`; secret output yields `OwnedSecretRegion`. The sealed
marker cannot be implemented downstream. Neither state exposes Clone, Debug,
reset, snapshots, import/export, public compression or a CPU backend selector.

Canonical bit tails put significant bits in the high end of the final byte;
unused low bits must be zero. Only consuming finalization accepts a tail.
Updates admit length before mutation. Public-output errors preserve the whole
destination; secret-output errors clear the whole destination, including wrong
sizes. Secret output clears on Drop. Failed updates retain unchanged live state.

Both profiles share five fixed owned byte regions: chaining state, block and
padding storage, u128 message length, buffered count, and output staging.
Compression reads the block directly, without a separate schedule allocation
or copy. Mandatory `brynja-core` compiler-resistant clearing destroys the
source-owned regions on Drop, cancellation, consuming errors and recoverable
unwind; block storage is also cleared between blocks. Cleanup does not require
the optional sanitization adapter and remains non-panicking. Debug buffer
invariants detect impossible private offsets before writes in development.

No claim covers registers, compiler-created copies/spills, caches, moves,
swap, dumps, DMA, caller copies, `mem::forget`, abort, termination or power
loss. No pinned/locked memory, independent review or FIPS validation exists.

## Reproducible verification

The RFC Editor and IETF RFC 1321 plaintext copies were byte-identical on
2026-09-06. Their pinned SHA-256 is
`284a79d148400d9cd2a423211d1103b5cef0fb9256a4cbe6d7ebe5197c3149dd`.
The local RFC inventory retains the publication and its original notices.
Verified errata 551/585 correct round-index notation and 552 corrects wording;
550/553 concern the unused C driver. Held 6193 concerns its zero-duration
timing division; rejected 7814 does not amend authority. Our fixed-width Rust
implementation does not import that driver.
Seven appendix A.5 known answers are transcribed in the test vector file;
none is claimed to be a NIST certification vector. Additional million-byte
and bit-boundary checks complement a separately written Python bit oracle.
Byte-aligned oracle results also match hashlib MD5. Python/OpenSSL stays
test-only; production crypto is entirely first-party Rust.

```sh
cargo test --locked -p brynja-legacy-md5
cargo test --locked --manifest-path assurance/md5-public-api/Cargo.toml
python3 scripts/md5/check-md5-differential.py
python3 scripts/md5/check-md5-package.py
python3 scripts/md5/check-md5.py
python3 scripts/md5/test-md5.py
scripts/md5/check-md5-codegen.sh 1.90.0
scripts/md5/check-md5-codegen.sh 1.98.1
scripts/zeroization/check-zeroization-miri.sh --group md5
```

The bounded adapter rejects malformed/oversized requests before computation.
The differential campaign covers 1,136 messages and ten malformed requests.
Miri targets owner, padding, error and unwind behavior; million-byte and
repeated vectors run natively/under ASan, not interpreted Miri. Kani checks
the u128 admission domain using its declared separate Rust 1.90 toolchain.
Compiler contracts bind the actual owner Drop/wipe and five clearing regions;
they do not prove removal of every compiler or physical copy.

No external crate is added. New crypto requires an exceptional pentest before
tagging. This internal milestone selects zero packages for publication.
