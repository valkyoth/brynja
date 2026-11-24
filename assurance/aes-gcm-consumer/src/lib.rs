//! External path consumer; build each route separately so feature unification
//! cannot mask a missing facade feature.
//!
//! Partial overlap is not exact in-place use:
//! ```compile_fail,E0502
//! use aes_gcm_consumer::crypto::aes_gcm::Aes128Gcm;
//! fn bad(sender: &mut Aes128Gcm<'_>, buf: &mut [u8; 17], work: &mut [u8; 16]) {
//!     let _ = sender.seal_next(&[], &buf[..16], &mut buf[1..], work);
//! }
//! ```
//! Scratch may not alias a live in-place destination:
//! ```compile_fail,E0499
//! use aes_gcm_consumer::crypto::aes_gcm::Aes128Gcm;
//! fn bad(receiver: &Aes128Gcm<'_>, buf: &mut [u8; 16]) {
//!     let _ = receiver.open_in_place(&[0; 12], &[], &[0; 16], buf, buf);
//! }
//! ```
//! A default receiver cannot open a general-width IV, even with separate buffers:
//! ```compile_fail,E0308
//! use aes_gcm_consumer::crypto::aes_gcm::Aes128Gcm;
//! fn bad(receiver: &Aes128Gcm<'_>, iv: &[u8; 16], tag: &[u8; 16]) {
//!     let _ = receiver.open(iv, &[], tag, &[], &mut [], &mut []);
//! }
//! ```
//! An explicitly general-width owner cannot open the default width in place:
//! ```compile_fail,E0308
//! use aes_gcm_consumer::crypto::aes_gcm::Aes256Gcm;
//! fn bad(receiver: &Aes256Gcm<'_, 16, 60>, iv: &[u8; 12], tag: &[u8; 16]) {
//!     let _ = receiver.open_in_place(iv, &[], tag, &mut [], &mut []);
//! }
//! ```
//! Neither raw primitive becomes public just because GCM needs it:
//! ```compile_fail,E0603
//! use aes_gcm_consumer::crypto::aes::Aes128ExpandedKey;
//! ```
//! ```compile_fail,E0603
//! use aes_gcm_consumer::crypto::ghash::Ghash;
//! ```
#![no_std]
#![forbid(unsafe_code)]

#[cfg(feature = "facade")]
pub use brynja::crypto;
#[cfg(feature = "direct")]
pub use brynja_crypto as crypto;

use crypto::aes_gcm::{Aes128Gcm, Aes192Gcm, Aes256Gcm, GcmError};
mod general_iv;
pub use general_iv::exercise_general_iv;

/// Exercise all three public owners on host; compile the same calls on Cortex-M.
pub fn exercise() -> Result<(), GcmError> {
    // Public NIST AES-GCM example 1 at each key width.
    const KEY: &[u8; 32] =
        b"\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08\xfe\xff\xe9\x92\x86\x65\x73\x1c\x6d\x6a\x8f\x94\x67\x30\x83\x08";
    macro_rules! check {
        ($owner:ident, $width:literal, $schedule:literal, $empty_tag:expr) => {{
            let raw: &[u8; $width] = KEY.first_chunk().ok_or(GcmError::Length)?;
            let mut storage = [0; $schedule];
            let first = 0xfacedbaddecaf888;
            let mut sender = $owner::<16>::from_reserved_range(
                raw,
                &mut storage,
                0xcafebabe_u32.to_be_bytes(),
                first,
                2,
            )?;
            let (iv, tag) = sender.seal_next(&[], &[], &mut [], &mut [])?;
            assert_eq!(tag, u128::to_be_bytes($empty_tag));
            assert_eq!(
                iv,
                [
                    0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88
                ]
            );
            let (mut data, mut work) = ([0x42; 19], [0x77; 19]);
            let (iv, tag) = sender.seal_next_in_place(b"aad", &mut data, &mut work)?;
            assert_eq!(work, [0; 19]);
            drop(sender);
            assert_eq!(storage, [0; $schedule]);
            let mut receiver = $owner::<16>::for_open(raw, &mut storage)?;
            let ct = data;
            assert_eq!(
                receiver.open_in_place(&iv, b"other", &tag, &mut data, &mut work),
                Err(GcmError::Authentication)
            );
            assert_eq!(data, ct);
            receiver.open(&iv, b"aad", &tag, &ct, &mut data, &mut work)?;
            assert_eq!(data, [0x42; 19]);
            assert_eq!(work, [0; 19]);
            assert_eq!(
                receiver.seal_next_in_place(&[], &mut [], &mut []),
                Err(GcmError::Exhausted)
            );
        }};
    }
    check!(Aes128Gcm, 16, 176, 0x3247184b3c4f69a44dbcd22887bbb418);
    check!(Aes192Gcm, 24, 208, 0xc835aa88aebbc94f5a02e179fdcfc3e4);
    check!(Aes256Gcm, 32, 240, 0xfd2caa16a5832e76aa132c1453eeda7e);
    Ok(())
}

#[test]
fn public_owners() -> Result<(), GcmError> {
    exercise()
}

#[test]
fn general_iv_known_answers() -> Result<(), GcmError> {
    exercise_general_iv()
}
