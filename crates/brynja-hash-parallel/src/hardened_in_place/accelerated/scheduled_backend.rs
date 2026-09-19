use super::super::backend::State;
use super::{ParallelHashError as Error, api, backend::Output};
use crate::Fips202BitString;
use brynja_hash_sha3::HardenedSha3SecretOutput;

pub(super) struct Scheduled<S, B> {
    pub(super) state: S,
    pub(super) scratch: B,
}
macro_rules! port {
    ($state:ident, $reader:ident) => {
        impl<'s, 'a> State for Scheduled<api::$state<'s, 'a>, &'s mut [u8]> {
            type Reader = Output<api::$reader<'s, 'a>, &'s mut [u8]>;
            fn check(&mut self) -> Result<(), Error> {
                self.state.update(&[]).map_err(Error::from)
            }
            fn update(&mut self, input: &[u8]) -> Result<(), Error> {
                self.state.update(input).map_err(Error::from)
            }
            fn finish(mut self) -> Result<Self::Reader, Error> {
                self.check()?;
                Ok(Output::new(self.state.finalize_xof()?, self.scratch))
            }
            // Ordered roots consume already-computed typed leaves, never raw
            // input. This shared-trait method is deliberately unavailable.
            fn leaf<'out>(
                &mut self,
                _: Fips202BitString<'_>,
                output: &'out mut [u8; 64],
            ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
                let _ = brynja_core::clear_owned_region(output);
                Err(Error::StateConsumed)
            }
        }
    };
}
port!(Cshake128, Cshake128Reader);
port!(Cshake256, Cshake256Reader);
