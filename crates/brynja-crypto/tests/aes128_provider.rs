//! AES-128 mock-provider lifecycle checks; no hardware qualification.
#![forbid(unsafe_code)]
use brynja_crypto::aes::Aes128Key as SoftwareKey;
use brynja_crypto::aes::provider::{Aes128Backend as AesBackend, Aes128ProviderKey as ProviderKey};
const KEY_BYTES: usize = 16;
// FIPS 197 Appendix C: ascending key bytes and plaintext 001122...eeff.
const CIPHER: [u8; 16] = [
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
];
#[path = "aes_provider_common/mod.rs"]
mod contracts;
