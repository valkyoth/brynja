//! Real accelerated HMAC consumers; compilation never grants CPU authority.
#![no_std]
#![forbid(unsafe_code)]

use brynja_mac_hmac::{execution::Hmac, *};

macro_rules! probes {
    ($module:ident, $algorithm:ty) => {
        probes!($module, $algorithm, Sha2BitString);
    };
    ($module:ident, $algorithm:ty, $bits:ident) => {
        pub mod $module {
            use super::*;

            #[inline(never)]
            pub fn construct_static<'a>(
                owner: &'a execution::Authority,
                key: &[u8],
            ) -> Result<Hmac<'a, $algorithm>, Error> {
                Hmac::from_static(owner, key)
            }

            #[cfg(feature = "runtime-execution")]
            #[inline(never)]
            pub fn construct_runtime<'a>(
                owner: &'a execution::RuntimeAuthority,
                key: &[u8],
            ) -> Result<Hmac<'a, $algorithm>, Error> {
                Hmac::from_runtime(owner, key)
            }

            #[inline(never)]
            pub fn public(state: Hmac<'_, $algorithm>, output: &mut [u8]) -> Result<(), Error> {
                let tag = state.finalize_tag(output)?;
                core::hint::black_box(tag.as_bytes());
                Ok(())
            }

            #[inline(never)]
            pub fn secret(state: Hmac<'_, $algorithm>, output: &mut [u8]) -> Result<(), Error> {
                let tag = state.finalize_secret(output)?;
                core::hint::black_box(tag.expose());
                drop(tag);
                Ok(())
            }

            #[inline(never)]
            pub fn verify(state: Hmac<'_, $algorithm>, candidate: &[u8]) -> Result<bool, Error> {
                Ok(state.verify(candidate)?.expose_public())
            }

            #[inline(never)]
            pub fn public_bits(
                state: Hmac<'_, $algorithm>,
                input: $bits<'_>,
                output: &mut [u8],
            ) -> Result<(), Error> {
                let tag = state.finalize_bits_tag(input, output)?;
                core::hint::black_box(tag.as_bytes());
                Ok(())
            }

            #[inline(never)]
            pub fn secret_bits(
                state: Hmac<'_, $algorithm>,
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
                state: Hmac<'_, $algorithm>,
                input: $bits<'_>,
                candidate: &[u8],
            ) -> Result<bool, Error> {
                Ok(state.verify_bits(input, candidate)?.expose_public())
            }

            #[inline(never)]
            pub fn cancel(state: Hmac<'_, $algorithm>) {
                state.cancel();
            }

            #[inline(never)]
            pub fn update_cancel(
                mut state: Hmac<'_, $algorithm>,
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
