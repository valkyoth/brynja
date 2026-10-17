//! Curated sha3 facade. Leaf-only integration and conformance exports are excluded.
//!
//! Reexported types retain their inherent leaf methods; this is not a sandbox
//! against an application explicitly enabling a leaf's test-only features.

pub use brynja_hash_sha3::{
    Cshake128, Cshake128Error, Cshake128Reader, Cshake256, Cshake256Error, Cshake256Reader,
    EncodedBitLength, EncodedInteger, ExtendableOutput, Fips202BitString, Fips202BitsError,
    Fips202Output, HardenedCshake128, HardenedCshake128Reader, HardenedCshake256,
    HardenedCshake256Reader, HardenedFips202Construction, HardenedFips202State, HardenedSha3_224,
    HardenedSha3_256, HardenedSha3_384, HardenedSha3_512, HardenedSha3Error,
    HardenedSha3SecretOutput, HardenedShake128, HardenedShake128Reader, HardenedShake256,
    HardenedShake256Reader, Sha3_224, Sha3_224Digest, Sha3_224Error, Sha3_256, Sha3_256Digest,
    Sha3_256Error, Sha3_384, Sha3_384Digest, Sha3_384Error, Sha3_512, Sha3_512Digest,
    Sha3_512Error, Sha3PublicDeclassification, Shake128, Shake128Error, Shake128Reader, Shake256,
    Shake256Error, Shake256Reader, Sp800185EncodingError, Sp800185Integer, XofReader, bytepad,
    cshake128, cshake128_bits, cshake256, cshake256_bits, encode_string, left_encode,
    left_encode_u128, right_encode, right_encode_u128, sha3_224, sha3_224_bits, sha3_256,
    sha3_256_bits, sha3_384, sha3_384_bits, sha3_512, sha3_512_bits, shake128, shake128_bits,
    shake256, shake256_bits,
};

#[cfg(feature = "keccak-batch")]
pub use brynja_hash_sha3::batch;
#[cfg(any(
    feature = "sha3-static-execution",
    feature = "sha3-runtime-execution",
    feature = "sha3-hardened-execution"
))]
pub use brynja_hash_sha3::execution;
#[cfg(feature = "keccak-hardened-batch")]
pub use brynja_hash_sha3::hardened_batch;
#[cfg(feature = "sha3-hardened-execution")]
pub use brynja_hash_sha3::hardened_execution;
pub use brynja_hash_sha3::{FixedOutput, Update};
