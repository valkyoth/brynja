use super::super::backend::{Reader, State};
use super::{ParallelHashError as Error, api};
use crate::{Fips202BitString, Fips202Output};
use brynja_hash_sha3::{HardenedSha3SecretOutput, Sha3PublicDeclassification};

pub(super) struct Backend<S, L, B> {
    pub(super) state: S,
    pub(super) leaf: L,
    pub(super) scratch: B,
}
pub(super) struct Output<R, B> {
    state: R,
    scratch: B,
}
impl<R, B> Output<R, B> {
    pub(super) fn new(state: R, scratch: B) -> Self {
        Self { state, scratch }
    }
}
macro_rules! port {
    ($state:ident, $reader:ident, $leaf:ident, $size:expr) => {
        impl<'s, 'a> State for Backend<api::$state<'s, 'a>, &'s mut api::$leaf<'a>, &'s mut [u8]> {
            type Reader = Output<api::$reader<'s, 'a>, &'s mut [u8]>;
            fn check(&mut self) -> Result<(), Error> {
                self.state.update(&[])?;
                // The leaf is idle between complete leaf scopes. Restart an
                // empty scope to validate its original authority, not its report.
                self.leaf.with(|state| state.cancel())?;
                Ok(())
            }
            fn update(&mut self, input: &[u8]) -> Result<(), Error> {
                self.check()?;
                self.state.update(input).map_err(Error::from)
            }
            fn finish(mut self) -> Result<Self::Reader, Error> {
                self.check()?;
                Ok(Output {
                    state: self.state.finalize_xof()?,
                    scratch: self.scratch,
                })
            }
            fn leaf<'out>(
                &mut self,
                input: Fips202BitString<'_>,
                output: &'out mut [u8; 64],
            ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
                self.check()?;
                let bytes = output.get_mut(..$size).ok_or(Error::SecretMemory)?;
                self.leaf
                    .with(|state| state.finalize_bits_xof(input)?.squeeze_secret(bytes))?
                    .map_err(Error::from)
            }
        }
        impl Reader for Output<api::$reader<'_, '_>, &mut [u8]> {
            fn read_public(&mut self, output: &mut [u8]) -> Result<(), Error> {
                self.state
                    .squeeze_public_with_scratch(
                        output,
                        self.scratch,
                        Sha3PublicDeclassification::acknowledge(),
                    )
                    .map_err(Error::from)
            }
            fn read_secret<'out>(
                &mut self,
                output: &'out mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
                self.state.squeeze_secret(output).map_err(Error::from)
            }
            fn public(self, output: Fips202Output<'_>) -> Result<(), Error> {
                self.state
                    .squeeze_final_bits_public(
                        output,
                        self.scratch,
                        Sha3PublicDeclassification::acknowledge(),
                    )
                    .map_err(Error::from)
            }
            fn secret<'out>(
                self,
                output: &'out mut [u8],
                valid: u8,
            ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
                self.state
                    .squeeze_final_bits_secret(output, valid)
                    .map_err(Error::from)
            }
        }
    };
}
port!(Cshake128, Cshake128Reader, Shake128Workspace, 32);
port!(Cshake256, Cshake256Reader, Shake256Workspace, 64);
