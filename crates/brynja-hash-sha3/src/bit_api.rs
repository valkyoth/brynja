use crate::{
    Fips202BitString, Fips202Output, Sha3_224, Sha3_224Digest, Sha3_224Error, Sha3_256,
    Sha3_256Digest, Sha3_256Error, Sha3_384, Sha3_384Digest, Sha3_384Error, Sha3_512,
    Sha3_512Digest, Sha3_512Error, Shake128, Shake128Error, Shake256, Shake256Error,
};

/// Computes SHA3-224 over one canonical arbitrary-bit string.
pub fn sha3_224_bits(input: Fips202BitString<'_>) -> Result<Sha3_224Digest, Sha3_224Error> {
    Sha3_224::new().finalize_bits(input)
}

/// Computes SHA3-256 over one canonical arbitrary-bit string.
pub fn sha3_256_bits(input: Fips202BitString<'_>) -> Result<Sha3_256Digest, Sha3_256Error> {
    Sha3_256::new().finalize_bits(input)
}

/// Computes SHA3-384 over one canonical arbitrary-bit string.
pub fn sha3_384_bits(input: Fips202BitString<'_>) -> Result<Sha3_384Digest, Sha3_384Error> {
    Sha3_384::new().finalize_bits(input)
}

/// Computes SHA3-512 over one canonical arbitrary-bit string.
pub fn sha3_512_bits(input: Fips202BitString<'_>) -> Result<Sha3_512Digest, Sha3_512Error> {
    Sha3_512::new().finalize_bits(input)
}

/// Computes SHAKE128 over one canonical arbitrary-bit string.
pub fn shake128_bits(
    input: Fips202BitString<'_>,
    output: Fips202Output<'_>,
) -> Result<(), Shake128Error> {
    Shake128::new()
        .finalize_bits_xof(input)?
        .squeeze_final_bits(output)
}

/// Computes SHAKE256 over one canonical arbitrary-bit string.
pub fn shake256_bits(
    input: Fips202BitString<'_>,
    output: Fips202Output<'_>,
) -> Result<(), Shake256Error> {
    Shake256::new()
        .finalize_bits_xof(input)?
        .squeeze_final_bits(output)
}
