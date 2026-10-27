//! Real monomorphized HMAC consumers for emitted-code inspection.
#![no_std]
#![forbid(unsafe_code)]

use brynja_mac_hmac::*;

macro_rules! probes {
    ($module:ident, $algorithm:ty) => {
        probes!($module, $algorithm, Sha2BitString);
    };
    ($module:ident, $algorithm:ty, $bits:ident) => {
        pub mod $module {
            use super::*;

            #[inline(never)]
            pub fn cancel(state: Hmac<$algorithm>) {
                state.cancel();
            }

            #[inline(never)]
            pub fn construct(key: &[u8]) -> Result<Hmac<$algorithm>, Error> {
                Hmac::new(key)
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
            pub fn verify(state: Hmac<$algorithm>, candidate: &[u8]) -> Result<(), Error> {
                state.verify(candidate)
            }

            #[inline(never)]
            pub fn public_bits(
                state: Hmac<$algorithm>,
                input: $bits<'_>,
                output: &mut [u8],
            ) -> Result<(), Error> {
                let tag = state.finalize_bits_tag(input, output)?;
                core::hint::black_box(tag.as_bytes());
                Ok(())
            }

            #[inline(never)]
            pub fn secret_bits(
                state: Hmac<$algorithm>,
                input: $bits<'_>,
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
                input: $bits<'_>,
                candidate: &[u8],
            ) -> Result<(), Error> {
                state.verify_bits(input, candidate)
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

probes!(sha224, Sha224);
probes!(sha256, Sha256);
probes!(sha384, Sha384);
probes!(sha512, Sha512);
probes!(sha512_224, Sha512_224);
probes!(sha512_256, Sha512_256);
probes!(sha3_224, Sha3_224, Fips202BitString);
probes!(sha3_256, Sha3_256, Fips202BitString);
probes!(sha3_384, Sha3_384, Fips202BitString);
probes!(sha3_512, Sha3_512, Fips202BitString);
probes!(general129, Sha512T<129>);
probes!(general511, Sha512T<511>);
