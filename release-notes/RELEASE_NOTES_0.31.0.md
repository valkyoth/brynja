# v0.31.0 — Standalone Poly1305 (in development)

This internal milestone starts from v0.30.6. It does not select any crates for
publication. Its scope is the one-time authenticator, not key generation,
encryption, ChaCha20-Poly1305 (v0.31.1), or a hardware backend.

The [fixture](../assurance/poly1305/rfc8439.tsv) contains the worked example in
[RFC 8439 §2.5.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5.2)
and all eleven [Appendix A.3](https://www.rfc-editor.org/rfc/rfc8439.html#appendix-A.3)
cases. Each tab-separated row gives the section or vector ID, 32-byte key,
message and 16-byte expected tag, in wire-order hex. All bytes are public test
data. The expected tags come from the RFC, not from the reference program.

Run `python3 scripts/cryptography/test-poly1305-vectors.py` offline. Add
`--openssl` to also check the RFC answers and deterministic boundary cases
against an independent implementation. Neither Python nor OpenSSL will be a
runtime dependency. This tests the corpus and model, not a Rust implementation.

## Remaining before acceptance

- Build the portable `no_std` owner in `brynja-mac-poly1305`. Authentication
  and verification each consume a one-time key. Consuming a Rust owner prevents
  accidental reuse of that owner; it cannot prevent reimporting copied bytes.
- Check streaming partitions, exact and partial blocks, the empty message,
  full-length tag verification and altered tags. Check the length budget before
  changing state, and test clearing on completion, rejection and drop.
- Run the roadmap's arithmetic proofs, emitted-code and cleanup checks, and test
  direct and façade consumers on the supported compiler endpoints and bare metal.
  No production API, independent review, or target timing claim is made here.
