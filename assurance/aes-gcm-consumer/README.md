# Portable AES-GCM consumer

This `no_std` crate imports the public API as a downstream path dependency.
It runs NIST's empty-message example for each key size and checks receipt,
authentication failure, unchanged ciphertext and schedule clearing. Four
compile-fail examples cover partial overlap, scratch aliasing and attempts
to import the two raw primitive modules with only `aes-gcm` enabled.

From the repository root:

```sh
brynja-verify run aes_gcm public-consumer
brynja-verify run aes_gcm packaged-public-api
```

For a single host route:

```sh
cargo +1.90.0 test --locked --offline --manifest-path assurance/aes-gcm-consumer/Cargo.toml --features facade
```

Use `direct` **instead of** `facade` to test `brynja-crypto` without the facade.
The first check uses path dependencies. The second packages and unpacks the
first-party crates, verifies their files against the source, then checks the
resolved graph and runs the external tests against only those archives.
Both compile the consumer for `thumbv7em-none-eabi` on both Rust endpoints;
neither executes on the microcontroller or qualifies timing.

### Worked-example fixture

`tests/nist-worked.txt` contains all six examples for each of the three key
sizes in [NIST's GCM worked examples](https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_GCM.pdf).
Rows are in document order: key width, example number, key, IV, AAD,
plaintext, expected ciphertext, expected tag. Bytes are lowercase hex;
`-` denotes an empty byte string. The final example for each width uses
the published 96-bit tag. Repeated IVs are public test fixtures, **not**
an example of how an application should allocate nonces.

The source PDF SHA-256 is `55e822592257799a4f895d6f3cb4c15515a065c008087105fc2063d2e757b5ef`.
The offline archive runner pins the normalized fixture hash and never
derives expected values from Brynja. The set is not the GCMVS response-file
campaign or a validation certificate.

`src/general_iv.rs` contains a separate independent ciphertext/tag fixture
at each key width, for IVs of 8, 16 and 60 bytes. The file gives the public
inputs and the oracle used to generate them. No oracle library is linked
or required to replay the tests.
