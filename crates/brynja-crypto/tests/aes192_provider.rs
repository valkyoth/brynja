//! AES-192 mock-provider lifecycle checks; no hardware qualification.
#![forbid(unsafe_code)]
use brynja_crypto::aes::Aes192Key as SoftwareKey;
use brynja_crypto::aes::provider::{Aes192Backend as AesBackend, Aes192ProviderKey as ProviderKey};
const KEY_BYTES: usize = 24;
// FIPS 197 Appendix C: ascending key bytes and plaintext 001122...eeff.
const CIPHER: [u8; 16] = [
    0xdd, 0xa9, 0x7c, 0xa4, 0x86, 0x4c, 0xdf, 0xe0, 0x6e, 0xaf, 0x70, 0xa0, 0xec, 0x0d, 0x71, 0x91,
];
#[path = "aes_provider_common/mod.rs"]
mod contracts;
