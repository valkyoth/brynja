# brynja-aead-gcm

Enable `aes-gcm` for detached authenticated encryption or `gmac` for AAD-only authentication. No features are enabled by default. Each API supports AES-128, AES-192 and AES-256 without allocation. For example, import `brynja_aead_gcm::aes_gcm::Aes256Gcm` or `brynja_aead_gcm::gmac::Aes256Gmac`. The existing `brynja_crypto` and `brynja::crypto` imports refer to the same owners.

Reserve disjoint IV ranges durably before sending. Do not reuse a nonce under the same key, including across processes, restarts or GCM/GMAC use. Opening does not provide replay protection. Portable constructors never dispatch automatically. The separate `aes-gcm-execution` and `gmac-execution` features expose explicit paired backends; this extraction adds no platform or timing qualification.
