//! Real accelerated HMAC consumers; compilation never grants CPU authority.
#![no_std]
#![forbid(unsafe_code)]

use brynja_mac_hmac::{execution::Hmac, *};

macro_rules! probes {
    ($module:ident, $algorithm:ty) => {
        pub mod $module {
            use super::*;

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
probes!(sha3_224, Sha3_224);
probes!(sha3_256, Sha3_256);
probes!(sha3_384, Sha3_384);
probes!(sha3_512, Sha3_512);
probes!(general129, Sha512T<129>);
probes!(general511, Sha512T<511>);
