//! Exact-length, fixed-storage setup for streamed customization and keys.
mod engine;
#[cfg(test)]
mod tests;
use crate::{
    Fips202BitString, Kmac128, Kmac256, KmacError, KmacXof128, KmacXof256, backend::CshakeState,
};
use brynja_hash_sha3::{
    HardenedCshake128, HardenedCshake128Setup, HardenedCshake256, HardenedCshake256Setup,
};

/// Module-private completion authority: only the checked setup engine can make
/// it. The existing core never accepts an arbitrary cSHAKE state as a KMAC key.
pub(crate) struct Prepared<S: CshakeState>(S);
impl<S: CshakeState> Prepared<S> {
    pub(crate) fn into_state(self) -> S {
        self.0
    }
}
trait Domain {
    type State: CshakeState;
    const RATE: usize;
    const STRENGTH: u128;
    fn new(custom_bits: u128) -> Result<Self, KmacError>
    where
        Self: Sized;
    fn custom(&mut self, input: Fips202BitString<'_>) -> Result<(), KmacError>;
    fn finish(&mut self) -> Result<Self::State, KmacError>;
    fn wipe(&mut self);
}
macro_rules! domain {
    ($setup:ty,$state:ty,$rate:literal,$strength:literal) => {
        impl Domain for $setup {
            type State = $state;
            const RATE: usize = $rate;
            const STRENGTH: u128 = $strength;
            fn new(custom_bits: u128) -> Result<Self, KmacError> {
                let mut setup = <$setup>::new(32, custom_bits)?;
                setup.name(
                    Fips202BitString::new(b"KMAC", 8).map_err(|_| KmacError::InvalidBitString)?,
                )?;
                Ok(setup)
            }
            fn custom(&mut self, input: Fips202BitString<'_>) -> Result<(), KmacError> {
                self.customization(input).map_err(KmacError::from)
            }
            fn finish(&mut self) -> Result<Self::State, KmacError> {
                self.finish_erasing_source().map_err(KmacError::from)
            }
            fn wipe(&mut self) {
                self.wipe_in_place();
            }
        }
    };
}
domain!(HardenedCshake128Setup, HardenedCshake128, 168, 128);
domain!(HardenedCshake256Setup, HardenedCshake256, 136, 256);

macro_rules! setup {
    ($name:ident,$domain:ty,$fixed:ident,$xof:ident) => {
        /// Incremental production-strength KMAC setup. Declare exact public key
        /// and customization bit lengths; supply customization first, explicitly
        /// finish it, then supply key fragments. No whole-key buffer is allocated.
        /// Errors and unwinding clear owned storage and terminate setup. Original
        /// caller buffers/copies and fatal aborts remain outside this guarantee.
        /// Neither Send, Sync, Copy, Clone nor Debug; no partial-completion oracle.
        #[doc = concat!("```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_mac_kmac::",stringify!($name),">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_mac_kmac::",stringify!($name),">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_mac_kmac::",stringify!($name),">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_mac_kmac::",stringify!($name),">();\n```")]
        #[doc = concat!("```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_mac_kmac::",stringify!($name),">();\n```")]
        pub struct $name(engine::Setup<$domain>);
        impl $name {
            /// Declare public lengths. Keys shorter than the selected strength reject.
            pub fn new(key_bits:u128, customization_bits:u128)->Result<Self,KmacError>{engine::Setup::new(key_bits,customization_bits).map(Self)}
            /// Append canonical low-bit-first S fragments, without inter-fragment padding.
            pub fn customization(&mut self,input:Fips202BitString<'_>)->Result<(),KmacError>{self.0.custom(input)}
            /// Complete S and initialize the exact bytepad key prefix. Call even for empty S.
            pub fn finish_customization(&mut self)->Result<(),KmacError>{self.0.finish_custom()}
            /// Append canonical low-bit-first key fragments; exact declared length is enforced.
            pub fn key(&mut self,input:Fips202BitString<'_>)->Result<(),KmacError>{self.0.key(input)}
            /// Complete key padding and transfer into fixed-output KMAC.
            pub fn finish(mut self)->Result<$fixed,KmacError>{self.0.finish().map($fixed::from_prepared)}
            /// Complete the same setup and transfer into KMACXOF.
            pub fn finish_xof(mut self)->Result<$xof,KmacError>{self.0.finish().map($xof::from_prepared)}
            /// Explicitly cancel and erase owned storage.
            pub fn cancel(self) {}
        }
    };
}
setup!(Kmac128Setup, HardenedCshake128Setup, Kmac128, KmacXof128);
setup!(Kmac256Setup, HardenedCshake256Setup, Kmac256, KmacXof256);
