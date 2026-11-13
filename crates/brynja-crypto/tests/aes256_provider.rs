//! AES-256 mock-provider lifecycle checks; no hardware qualification.
#![forbid(unsafe_code)]
use brynja_crypto::aes::Aes256Key as SoftwareKey;
use brynja_crypto::aes::provider::{Aes256Backend as AesBackend, Aes256ProviderKey as ProviderKey};
const KEY_BYTES: usize = 32;
// FIPS 197 Appendix C: ascending key bytes and plaintext 001122...eeff.
const CIPHER: [u8; 16] = [
    0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf, 0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
];
#[path = "aes_provider_common/mod.rs"]
mod contracts;
