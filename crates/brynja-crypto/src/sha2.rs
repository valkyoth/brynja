//! Curated sha2 facade. Leaf-only integration and conformance exports are excluded.
//!
//! Reexported types retain their inherent leaf methods; this is not a sandbox
//! against an application explicitly enabling a leaf's test-only features.

pub use brynja_hash_sha2::{
    BitString, BitStringError, FixedOutput, HardenedSha2Error, HardenedSha2State, HardenedSha224,
    HardenedSha256, HardenedSha384, HardenedSha512, HardenedSha512_224, HardenedSha512_256,
    PublicDeclassification, Sha224, Sha224Digest, Sha224Error, Sha256, Sha256Digest, Sha256Error,
    Sha384, Sha384Digest, Sha384Error, Sha512, Sha512_224, Sha512_224Digest, Sha512_224Error,
    Sha512_256, Sha512_256Digest, Sha512_256Error, Sha512Digest, Sha512Error, Update, sha224,
    sha224_bits, sha256, sha256_bits, sha384, sha384_bits, sha512, sha512_224, sha512_224_bits,
    sha512_256, sha512_256_bits, sha512_bits,
};

#[cfg(feature = "sha256-batch")]
pub use brynja_hash_sha2::batch;
#[cfg(feature = "sha512-batch")]
pub use brynja_hash_sha2::batch512;
#[cfg(any(
    feature = "sha2-static-execution",
    feature = "sha2-runtime-execution",
    feature = "sha2-hardened-execution"
))]
pub use brynja_hash_sha2::execution;
#[cfg(feature = "sha256-hardened-batch")]
pub use brynja_hash_sha2::hardened_batch;
#[cfg(feature = "sha512-hardened-batch")]
pub use brynja_hash_sha2::hardened_batch512;
#[cfg(feature = "sha2-hardened-execution")]
pub use brynja_hash_sha2::hardened_execution;
#[cfg(feature = "general-sha512-t")]
pub use brynja_hash_sha2::{
    HardenedSha512T, Sha512T, Sha512TBits, Sha512TDigest, Sha512TError, Sha512TSecretDigest,
    hardened_sha512_t_bits_public, hardened_sha512_t_bits_secret, hardened_sha512_t_public,
    hardened_sha512_t_secret, sha512_t, sha512_t_bits,
};
