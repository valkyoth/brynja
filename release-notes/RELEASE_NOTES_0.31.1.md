# v0.31.1 — Portable ChaCha20-Poly1305 (in development)

This internal milestone follows v0.31.0. No crate is selected for publication.
The [development leaf](../crates/brynja-aead-chacha20poly1305/README.md) exposes
separate sending and receiving owners. It requires no allocation or unsafe
code. The sender adopts an application-reserved prefix and counter range;
invalid lengths consume no nonce and keyed work cannot roll a nonce back.
The opener authenticates the ciphertext before decrypting into scratch.
Both APIs commit to the destination only on success.

The [offline replay](../scripts/cryptography/check-chacha20poly1305-vectors.py)
reads the pinned RFC 8439 text and checks the published answers in §2.8.2 and
Appendix A.5 using the portable ChaCha20 and Poly1305 crates. It checks the
counter-zero one-time key, AAD and ciphertext padding, both little-endian length
fields, the full tag, and counter-one decryption. Eight controls change one
field at a time in the first example and require rejection. The fixture uses
public data and is not an API example for handling application secrets. Both
records also exercise seal/open through the leaf in both buffer layouts,
including rejection of a change to each tag byte without releasing plaintext.

Run `python3 scripts/cryptography/check-chacha20poly1305-vectors.py --rust 1.90.0`
or select `1.100.0`. Add `--oracle` to cross-check both messages against the
locally installed Python `cryptography` AEAD. The normal check needs no Python
cryptography package, and the library gains no external dependency.

Enable `chacha20poly1305` on either development façade, or import the leaf
directly. Run `python3 scripts/cryptography/check-poly1305-packages.py --aead`
to test all three routes from locally staged registry archives, with both
Rust endpoints and a Cortex-M compile check. Without opt-in neither façade
resolves the AEAD or either of its primitive crates. Nothing is uploaded.

Remaining work is tracked in the [release plan](../docs/RELEASE_PLAN.md#v0311---complete-chacha20-poly1305):

- The [portable assurance record](../docs/assurance/chacha20poly1305-portable.md)
  covers 813 differential records per compiler, 40 software interruptions and
  three Kani proofs, with explicit limits.
- The linked open-path review covers both Rust endpoints on Linux x86-64.
  Requirement BRY-REQ-CRYPTO-0009 now records the portable implementation;
  its detached AEAD register entry distinguishes caller-owned plaintext from
  owned secret output. The API borrows the key, preserves the destination on
  failure and does not generate keys. The two official RFC answers also ship
  as leaf unit tests.
- Scoped pentest/retest disposition, final gate, green GitHub and tag remain
  release steps. Acceleration belongs to v0.31.2.
