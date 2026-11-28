# v0.31.1 — Portable ChaCha20-Poly1305 (in development)

This internal milestone follows v0.31.0. No crate is selected for publication.
The first change is a test fixture: there is **no public seal/open API yet**.

The [offline replay](../scripts/cryptography/check-chacha20poly1305-vectors.py)
reads the pinned RFC 8439 text and checks the published answers in §2.8.2 and
Appendix A.5 using the portable ChaCha20 and Poly1305 crates. It checks the
counter-zero one-time key, AAD and ciphertext padding, both little-endian length
fields, the full tag, and counter-one decryption. Eight controls change one
field at a time in the first example and require rejection. The fixture uses
public data and is not an API example for handling application secrets.

Run `python3 scripts/cryptography/check-chacha20poly1305-vectors.py --rust 1.90.0`
or select `1.100.0`. Add `--oracle` to cross-check both messages against the
locally installed Python `cryptography` AEAD. The normal check needs no Python
cryptography package, and the library gains no external dependency.

Remaining work is tracked in the [release plan](../docs/RELEASE_PLAN.md#v0311---complete-chacha20-poly1305):

- Implement the portable leaf with a 96-bit nonce and full 16-byte tag.
  Check message, counter and MAC framing limits before changing buffers.
  Reserve each sending nonce before keyed work; the caller remains responsible
  for uniqueness across owners and restarts.
- Exercise the public in-place and disjoint operations against known answers,
  including authentication rejection, exhaustion, clearing and unwind paths.
- Verify the no_std and façade imports, package contents, and bounds and
  comparison evidence before the final gate. Acceleration belongs to v0.31.2.
