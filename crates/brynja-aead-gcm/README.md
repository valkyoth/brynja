# brynja-aead-gcm

Enable `aes-gcm` for detached authenticated encryption or `gmac` for AAD-only authentication. No features are enabled by default. Each API supports AES-128, AES-192 and AES-256 without allocation. For example, import `brynja_aead_gcm::aes_gcm::Aes256Gcm` or `brynja_aead_gcm::gmac::Aes256Gmac`. The existing `brynja_crypto` and `brynja::crypto` imports refer to the same owners.

Reserve disjoint IV ranges durably before sending. Do not reuse a nonce under the same key, including across processes, restarts or GCM/GMAC use. Opening does not provide replay protection. Portable constructors never dispatch automatically. The separate `aes-gcm-execution` and `gmac-execution` features expose explicit paired backends; this extraction adds no platform or timing qualification.

A 64-bit counter is an IV format, not permission to send that much traffic. Limit records, total data and failed authentications across all owners of a key according to the protocol, and rotate the key before its limit. These senders construct prefix-and-counter IVs, not the static-IV XOR sequence numbers used by TLS 1.3 and QUIC.

Use the documented mode features rather than depending on the primitive crates' hidden `__mode` bridges. Those bridges are implementation interfaces, not stable public contracts or access controls.
