# Using AES-GCM and GMAC from a downstream package

Choose `aes-gcm` to encrypt and authenticate, or `gmac` to authenticate
cleartext. Both default to portable code. Import from `brynja_crypto` directly
or from `brynja::crypto` through the facade. The ordinary and paired families
both provide 128-, 192- and 256-bit key types. See the [portable round trip](../aead-portable-acceptance/README.md)
for key, IV and buffer ownership; use separate keys for GCM and GMAC.

If your deployment supports a native pair, opt into `aes-gcm-execution` or
`gmac-execution`. Require the pair **before importing a key**, then supply
`&pair` as the first constructor argument to the corresponding owner in
`execution`. This does not change ordinary constructors. See the
[platform and fallback rules](../../docs/assurance/aead-accelerated-development.md);
don't retry a failed operation through another backend.

## Reproduce the installation check

From the repository root, with Rust 1.90.0 and 1.100.0 installed:

```sh
python3 scripts/aes-gcm/check-installed-consumer.py
# Optional: Linux x86-64 with AES-NI, SSE2 and PCLMUL on all eligible CPUs.
python3 scripts/aes-gcm/check-installed-consumer.py --native-x86
```

Each command packages the library sources locally, checks the resolved
dependency graph against the unpacked archives, and uses `cargo install
--locked --offline` for the **consumer binary**, into a new temporary prefix
per compiler, import route and algorithm. It executes that installed binary,
not one from the checkout or the user's PATH. No crates.io publication,
user-wide installation, Go, or external vector ZIP is needed for these checks.
The same checks are registered under `aes_gcm` as
`installed-portable-consumer` and `installed-x86-consumer`.

| What is exercised | What the result means |
| --- | --- |
| Installed GCM consumer | At each key width, 26 known-answer/tag-length combinations from six NIST worked examples and their leftmost truncations. Each uses both buffer layouts: seal matches the expected IV, ciphertext and tag; a bad tag leaves the ciphertext or separate destination unchanged; valid open recovers the plaintext. The second send is rejected as exhausted. |
| Installed GMAC consumer | At each key width, 10 combinations from the two empty-payload examples (empty and nonempty AAD), with 12–16 byte tags. Generate, exhaust the reservation, reject the altered tag, then verify the correct tag. |
| General IVs and larger corpora | The install fixture uses 96-bit IVs. The existing [portable replay](../aead-portable-acceptance/README.md) and [paired replay](../../docs/assurance/aead-accelerated-development.md) cover general-IV hashing separately, including 13 representative IV widths in the Go corpus. This is not an exhaustive test of every possible IV length. |

The tests reconstruct published key/IV pairs to compare implementations.
Do **not** copy that reservation pattern into an application: sending ranges
must be unique under the key, durably allocated across restarts and senders.
Successful authentication alone does not provide replay protection.

Matching NIST examples is a functional result. Brynja does not have a
FIPS 140-3 validated module or a CMVP certificate. This check neither
qualifies timing on any platform nor resolves the Arm GHASH timing observation.
