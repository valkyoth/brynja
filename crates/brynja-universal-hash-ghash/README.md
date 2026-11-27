# brynja-universal-hash-ghash

Enable `hazmat-ghash` for allocation-free, incremental GHASH on pre-framed
blocks. The default build exposes no primitive. The caller supplies the hash
subkey, a 16-byte workspace, a byte budget and separate output storage.
`SecretHash` is an intermediate, not a tag: GHASH alone does not authenticate
messages. Use AES-GCM or GMAC for those constructions. This is not POLYVAL.

Portable construction never selects native execution. The optional
`ghash-runtime-execution` feature adds explicit backend selection with the
same platform and timing limitations as the compatibility API. The
`__mode` interfaces are for Brynja composition and are not stable user APIs.
Any dependent can name them when their features are enabled, including by
Cargo feature unification. They expose GHASH framing, not a security boundary.
Use `hazmat-ghash` for the supported raw API; `cpu` alone exposes no API.
