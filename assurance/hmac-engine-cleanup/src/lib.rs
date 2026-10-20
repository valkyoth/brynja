//! Real monomorphized HMAC consumers for emitted-code inspection.
#![no_std]
#![forbid(unsafe_code)]

use brynja_mac_hmac::*;

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
            pub fn verify(state: Hmac<$algorithm>, candidate: &[u8]) -> Result<bool, Error> {
                Ok(state.verify(candidate)?.expose_public())
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
probes!(sha3_224, Sha3_224);
probes!(sha3_256, Sha3_256);
probes!(sha3_384, Sha3_384);
probes!(sha3_512, Sha3_512);
probes!(general129, Sha512T<129>);
probes!(general511, Sha512T<511>);
