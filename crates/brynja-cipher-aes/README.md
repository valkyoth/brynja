# brynja-cipher-aes

Enable `hazmat-aes-block` for the portable AES-128, AES-192 and AES-256
single-block owners under `brynja_cipher_aes::aes`. They borrow caller
storage; ephemeral keys expand per operation and expanded keys cache their
schedule until clear or drop. Raw blocks do not authenticate messages.

There are no default features. Hardware execution is an explicit opt-in;
the existing CPU authority must admit the requested backend. The separate
`external-key-provider` feature supplies lifecycle contracts, not an HSM
driver. No block mode, timing qualification, or physical erasure guarantee
is provided. The `brynja_crypto::aes` compatibility API uses the same owners.
