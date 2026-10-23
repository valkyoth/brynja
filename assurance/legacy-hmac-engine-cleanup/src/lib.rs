//! Real portable legacy-HMAC callers, not whole-frame erasure probes.
#![no_std]
#![forbid(unsafe_code)]

use brynja_legacy_hmac::*;

macro_rules! probes {
    ($module:ident, $algorithm:ty) => {
        pub mod $module {
            use super::*;
            #[inline(never)]
            pub fn cancel(state: Hmac<$algorithm>) {
                state.cancel();
            }
            #[inline(never)]
            pub fn construct(key: &[u8]) -> Result<Hmac<$algorithm>, Error> {
                Hmac::new(LegacyUse::acknowledge(), key)
            }
            #[inline(never)]
            pub fn public(state: Hmac<$algorithm>, output: &mut [u8]) -> Result<(), Error> {
                let tag = state.finalize_tag(output)?;
                core::hint::black_box(tag.as_bytes());
                Ok(())
            }
            #[inline(never)]
            pub fn secret(state: Hmac<$algorithm>, output: &mut [u8]) -> Result<(), Error> {
                let tag = state.finalize_secret(output)?;
                core::hint::black_box(tag.expose());
                drop(tag);
                Ok(())
            }
            #[inline(never)]
            pub fn verify(state: Hmac<$algorithm>, candidate: &[u8]) -> Result<bool, Error> {
                Ok(state.verify(candidate)?.expose_public())
            }
            #[inline(never)]
            pub fn public_bits(
                state: Hmac<$algorithm>,
                input: BitString<'_>,
                output: &mut [u8],
            ) -> Result<(), Error> {
                let tag = state.finalize_bits_tag(input, output)?;
                core::hint::black_box(tag.as_bytes());
                Ok(())
            }
            #[inline(never)]
            pub fn secret_bits(
                state: Hmac<$algorithm>,
                input: BitString<'_>,
                output: &mut [u8],
            ) -> Result<(), Error> {
                let tag = state.finalize_bits_secret(input, output)?;
                core::hint::black_box(tag.expose());
                drop(tag);
                Ok(())
            }
            #[inline(never)]
            pub fn verify_bits(
                state: Hmac<$algorithm>,
                input: BitString<'_>,
                candidate: &[u8],
            ) -> Result<bool, Error> {
                Ok(state.verify_bits(input, candidate)?.expose_public())
            }
            #[inline(never)]
            pub fn update_cancel(
                mut state: Hmac<$algorithm>,
                input: &[u8],
                observer: fn(),
            ) -> Result<(), Error> {
                state.update(input)?;
                observer();
                state.cancel();
                Ok(())
            }
        }
    };
}

probes!(sha1, Sha1);
probes!(md5, Md5);
