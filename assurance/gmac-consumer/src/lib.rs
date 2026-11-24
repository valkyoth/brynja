//! Downstream consumer of only GMAC; each import route is compiled separately.
//! No raw AES, GHASH or ciphertext API is exposed:
//! ```compile_fail,E0603
//! use gmac_consumer::crypto::aes::Aes128ExpandedKey;
//! ```
//! ```compile_fail,E0603
//! use gmac_consumer::crypto::ghash::Ghash;
//! ```
//! ```compile_fail,E0603
//! use gmac_consumer::crypto::aes_gcm::Aes128Gcm;
//! ```
//! ```compile_fail,E0308
//! use gmac_consumer::crypto::gmac::{Aes128Gmac, GmacTag};
//! fn wrong(k: &Aes128Gmac<'_>, iv: &[u8; 12], tag: &GmacTag<12>) {
//!     let _ = k.verify(iv, b"record", tag);
//! }
//! ```
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "facade")]
pub use brynja::crypto;
#[cfg(feature = "direct")]
pub use brynja_crypto as crypto;

use crypto::gmac::{Aes128Gmac, Aes192Gmac, Aes256Gmac, GmacError, GmacTag};

/// Expected outcome in a public test vector.
#[derive(Clone, Copy)]
pub enum Operation {
    Generate,
    Verify,
    Reject,
}

/// Exercise exactly one published fixture. Reconstructing its IV as a one-message
/// reservation is solely for replay, not an example of allocating fresh IVs.
pub fn replay<const T: usize, const N: usize>(
    operation: Operation,
    key: &[u8],
    iv: &[u8; N],
    aad: &[u8],
    tag: &[u8; T],
) -> Result<bool, GmacError> {
    macro_rules! exercise {
        ($owner:ident, $size:literal) => {{
            let key = key.try_into().map_err(|_| GmacError::Length)?;
            let mut schedule = [0; $size];
            let ok = match operation {
                Operation::Generate => {
                    if let Ok(fixed) = <&[u8; 12]>::try_from(iv.as_slice()) {
                        let [a, b, c, d, counter @ ..] = *fixed;
                        let mut owner = $owner::<T>::from_reserved_range(
                            key,
                            &mut schedule,
                            [a, b, c, d],
                            u64::from_be_bytes(counter),
                            1,
                        )?;
                        let (issued, actual) = owner.authenticate_next(aad)?;
                        issued == *fixed && actual.as_bytes() == tag
                    } else {
                        let (prefix, suffix) = iv.split_at(N.saturating_sub(4));
                        let mut word = [0; 4];
                        word.get_mut(4usize.checked_sub(suffix.len()).ok_or(GmacError::Length)?..)
                            .ok_or(GmacError::Length)?
                            .copy_from_slice(suffix);
                        let mut owner = $owner::<T, N>::from_reserved_invocations(
                            key,
                            &mut schedule,
                            prefix,
                            u32::from_be_bytes(word),
                            1,
                        )?;
                        let (issued, actual) = owner.authenticate_next(aad)?;
                        issued == *iv && actual.as_bytes() == tag
                    }
                }
                Operation::Verify | Operation::Reject => {
                    let owner = $owner::<T, N>::for_verify(key, &mut schedule)?;
                    let result = owner.verify(iv, aad, &GmacTag::from_bytes(*tag));
                    match operation {
                        Operation::Reject => result == Err(GmacError::Authentication),
                        _ => result.is_ok(),
                    }
                }
            };
            Ok(ok && schedule.iter().all(|byte| *byte == 0))
        }};
    }
    match key.len() {
        16 => exercise!(Aes128Gmac, 176),
        24 => exercise!(Aes192Gmac, 208),
        32 => exercise!(Aes256Gmac, 240),
        _ => Err(GmacError::Length),
    }
}

#[cfg(test)]
#[path = "../../../crates/brynja-crypto/tests/fixtures/gmac_nist.rs"]
mod nist;

#[test]
fn consumer_authenticates_without_a_ciphertext_buffer() -> Result<(), GmacError> {
    let [key, iv, aad, tag] = nist::AES128;
    let key = nist::bytes::<16>(key)?;
    let iv = nist::bytes::<12>(iv)?;
    let aad = nist::bytes::<16>(aad)?;
    let tag = nist::bytes::<16>(tag)?;
    for operation in [Operation::Generate, Operation::Verify] {
        assert!(replay(operation, &key, &iv, &aad, &tag)?);
    }
    assert!(replay(Operation::Reject, &key, &iv, &[], &tag)?);
    Ok(())
}
