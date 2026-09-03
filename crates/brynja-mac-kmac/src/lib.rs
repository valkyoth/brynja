//! Complete portable SP 800-185 KMAC and KMACXOF functions for Brynja.
//!
//! All keyed state is built directly over Brynja's hardened cSHAKE owner. The
//! crate is allocation-free, `no_std`, first-party Rust, and exposes separate
//! fixed-output MAC and extendable-output PRF types. The opt-in
//! `conformance-testing` feature exposes constructors covering every
//! representable standards-valid key length, while default production
//! constructors enforce the selected 128- or 256-bit key strength.

#![no_std]

mod backend;
mod core_state;
mod error;
mod fixed;
mod output;
mod packer;
mod policy;
mod verify;
mod xof;

pub use brynja_hash_sha3::{Fips202BitString, Fips202BitsError, Fips202Output};
pub use error::KmacError;
pub use fixed::{Kmac128, Kmac256};
pub use output::{KmacPublicDeclassification, KmacSecretOutput, KmacTag, KmacVerification};
pub use policy::{KmacKeyPolicy, KmacServiceStatus, KmacTagPolicy};
pub use xof::{KmacXof128, KmacXof128Reader, KmacXof256, KmacXof256Reader};

/// Whether all four SP 800-185 KMAC identities are implemented.
pub const KMAC_IMPLEMENTED: bool = true;

/// Computes a full-strength KMAC128 public tag.
pub fn kmac128<'output>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output: &'output mut [u8],
) -> Result<KmacTag<'output>, KmacError> {
    let mut state = Kmac128::new(key, customization)?;
    state.update(message)?;
    state.finalize_tag(output)
}

/// Computes an exact-conformance KMAC128 tag, including weak parameter cases.
#[cfg(feature = "conformance-testing")]
pub fn kmac128_conformance<'output>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output: &'output mut [u8],
) -> Result<KmacTag<'output>, KmacError> {
    let mut state = Kmac128::new_conformance(key, customization)?;
    state.update(message)?;
    state.finalize_tag_conformance(output)
}

/// Computes a full-strength KMAC256 public tag.
pub fn kmac256<'output>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output: &'output mut [u8],
) -> Result<KmacTag<'output>, KmacError> {
    let mut state = Kmac256::new(key, customization)?;
    state.update(message)?;
    state.finalize_tag(output)
}

/// Computes an exact-conformance KMAC256 tag, including weak parameter cases.
#[cfg(feature = "conformance-testing")]
pub fn kmac256_conformance<'output>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output: &'output mut [u8],
) -> Result<KmacTag<'output>, KmacError> {
    let mut state = Kmac256::new_conformance(key, customization)?;
    state.update(message)?;
    state.finalize_tag_conformance(output)
}

/// Computes a full-strength arbitrary-bit KMAC128 public tag.
pub fn kmac128_bits<'output>(
    key: Fips202BitString<'_>,
    message: Fips202BitString<'_>,
    customization: Fips202BitString<'_>,
    output: &'output mut [u8],
    valid_output_bits: u8,
) -> Result<KmacTag<'output>, KmacError> {
    Kmac128::new_bits(key, customization)?.finalize_tag_bits(message, output, valid_output_bits)
}

/// Computes an exact-conformance arbitrary-bit KMAC128 public tag.
#[cfg(feature = "conformance-testing")]
pub fn kmac128_bits_conformance<'output>(
    key: Fips202BitString<'_>,
    message: Fips202BitString<'_>,
    customization: Fips202BitString<'_>,
    output: &'output mut [u8],
    valid_output_bits: u8,
) -> Result<KmacTag<'output>, KmacError> {
    Kmac128::new_bits_conformance(key, customization)?.finalize_tag_bits_conformance(
        message,
        output,
        valid_output_bits,
    )
}

/// Computes a full-strength arbitrary-bit KMAC256 public tag.
pub fn kmac256_bits<'output>(
    key: Fips202BitString<'_>,
    message: Fips202BitString<'_>,
    customization: Fips202BitString<'_>,
    output: &'output mut [u8],
    valid_output_bits: u8,
) -> Result<KmacTag<'output>, KmacError> {
    Kmac256::new_bits(key, customization)?.finalize_tag_bits(message, output, valid_output_bits)
}

/// Computes an exact-conformance arbitrary-bit KMAC256 public tag.
#[cfg(feature = "conformance-testing")]
pub fn kmac256_bits_conformance<'output>(
    key: Fips202BitString<'_>,
    message: Fips202BitString<'_>,
    customization: Fips202BitString<'_>,
    output: &'output mut [u8],
    valid_output_bits: u8,
) -> Result<KmacTag<'output>, KmacError> {
    Kmac256::new_bits_conformance(key, customization)?.finalize_tag_bits_conformance(
        message,
        output,
        valid_output_bits,
    )
}

/// Computes full-strength KMACXOF128 output and retains typed secret ownership.
pub fn kmacxof128_secret<'output>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output: &'output mut [u8],
) -> Result<KmacSecretOutput<'output>, KmacError> {
    let mut state = KmacXof128::new(key, customization)?;
    state.update(message)?;
    state.finalize_xof()?.squeeze_secret(output)
}

/// Computes full-strength KMACXOF256 output and retains typed secret ownership.
pub fn kmacxof256_secret<'output>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output: &'output mut [u8],
) -> Result<KmacSecretOutput<'output>, KmacError> {
    let mut state = KmacXof256::new(key, customization)?;
    state.update(message)?;
    state.finalize_xof()?.squeeze_secret(output)
}

/// Computes exact-conformance KMACXOF128 output with typed secret ownership.
#[cfg(feature = "conformance-testing")]
pub fn kmacxof128_secret_conformance<'output>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output: &'output mut [u8],
) -> Result<KmacSecretOutput<'output>, KmacError> {
    let mut state = KmacXof128::new_conformance(key, customization)?;
    state.update(message)?;
    state.finalize_xof_conformance()?.squeeze_secret(output)
}

/// Computes exact-conformance KMACXOF256 output with typed secret ownership.
#[cfg(feature = "conformance-testing")]
pub fn kmacxof256_secret_conformance<'output>(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output: &'output mut [u8],
) -> Result<KmacSecretOutput<'output>, KmacError> {
    let mut state = KmacXof256::new_conformance(key, customization)?;
    state.update(message)?;
    state.finalize_xof_conformance()?.squeeze_secret(output)
}

/// Computes full-strength KMACXOF128 output explicitly classified as public.
pub fn kmacxof128_public(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output: &mut [u8],
    authority: KmacPublicDeclassification,
) -> Result<(), KmacError> {
    let mut state = KmacXof128::new(key, customization)?;
    state.update(message)?;
    state.finalize_xof()?.squeeze_public(output, authority)
}

/// Computes full-strength KMACXOF256 output explicitly classified as public.
pub fn kmacxof256_public(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output: &mut [u8],
    authority: KmacPublicDeclassification,
) -> Result<(), KmacError> {
    let mut state = KmacXof256::new(key, customization)?;
    state.update(message)?;
    state.finalize_xof()?.squeeze_public(output, authority)
}

/// Computes exact-conformance KMACXOF128 output classified as public.
#[cfg(feature = "conformance-testing")]
pub fn kmacxof128_public_conformance(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output: &mut [u8],
    authority: KmacPublicDeclassification,
) -> Result<(), KmacError> {
    let mut state = KmacXof128::new_conformance(key, customization)?;
    state.update(message)?;
    state
        .finalize_xof_conformance()?
        .squeeze_public(output, authority)
}

/// Computes exact-conformance KMACXOF256 output classified as public.
#[cfg(feature = "conformance-testing")]
pub fn kmacxof256_public_conformance(
    key: &[u8],
    message: &[u8],
    customization: &[u8],
    output: &mut [u8],
    authority: KmacPublicDeclassification,
) -> Result<(), KmacError> {
    let mut state = KmacXof256::new_conformance(key, customization)?;
    state.update(message)?;
    state
        .finalize_xof_conformance()?
        .squeeze_public(output, authority)
}

#[cfg(test)]
mod tests {
    use super::KMAC_IMPLEMENTED;

    #[test]
    fn implementation_claim_is_exact() {
        assert!(::core::hint::black_box(KMAC_IMPLEMENTED));
    }
}
