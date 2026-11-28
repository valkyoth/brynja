# v0.31.0 — Standalone Poly1305 (in development)

This internal milestone starts from v0.30.6. It does not select any crates for
publication. Its scope is the one-time authenticator, not key generation,
encryption, ChaCha20-Poly1305 (v0.31.1), or a hardware backend.

The [fixture](../crates/brynja-mac-poly1305/tests/data/rfc8439.tsv) contains the worked example in
[RFC 8439 §2.5.2](https://www.rfc-editor.org/rfc/rfc8439.html#section-2.5.2)
and all eleven [Appendix A.3](https://www.rfc-editor.org/rfc/rfc8439.html#appendix-A.3)
cases. Each tab-separated row gives the section or vector ID, 32-byte key,
message and 16-byte expected tag, in wire-order hex. All bytes are public test
data. The expected tags come from the RFC, not from the reference program.

Run `python3 scripts/cryptography/test-poly1305-vectors.py` offline. Add
`--openssl` to also check the RFC answers and deterministic boundary cases
against an independent implementation. Neither Python nor OpenSSL will be a
runtime dependency. This tests the corpus and model, not a Rust implementation.

The unpublished [Rust leaf](../crates/brynja-mac-poly1305/README.md) now
implements portable streaming authentication and full-tag verification. Run
`cargo test --locked -p brynja-mac-poly1305` to exercise it against the RFC
answers at every two-part split, byte-at-a-time verification, altered tags,
the cumulative length limit, and key clearing. Add `--rust 1.90.0` or
`--rust 1.100.0` to the Python command to compare the optimized standalone
Rust consumer against all 56 public answers, with an altered-answer control.
Both compiler endpoints also compile the leaf for Cortex-M
(`thumbv7em-none-eabi`). These are functional and build checks.

## Remaining before acceptance

- Wire the opt-in façade route and exercise installed consumers.
- Run the roadmap's arithmetic proofs, emitted-code and cleanup checks, and test
  direct and façade consumers on the supported compiler endpoints and bare metal.
  The implementation is not independently verified or timing-qualified.
