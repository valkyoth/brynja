use super::super::backend::{Reader, State};
use super::{Fips202BitString, TupleHashError, cshake};
use crate::Fips202Output;
use brynja_hash_sha3::{HardenedSha3SecretOutput, Sha3PublicDeclassification};

// Only references move. Sponge, CPU scratch and transactional output staging
// remain in their borrowed caller storage until independent scope cleanup.
pub(super) struct Backend<S, B> {
    pub(super) state: S,
    pub(super) scratch: B,
}
macro_rules! port {
    ($state:ident, $reader:ident) => {
        impl<'s, 'a> State for Backend<cshake::$state<'s, 'a>, &'s mut [u8]> {
            type Reader = Backend<cshake::$reader<'s, 'a>, &'s mut [u8]>;
            fn update(&mut self, bytes: &[u8]) -> Result<(), TupleHashError> {
                self.state.update(bytes).map_err(TupleHashError::from)
            }
            fn finish(self, tail: Fips202BitString<'_>) -> Result<Self::Reader, TupleHashError> {
                Ok(Backend {
                    state: self.state.finalize_bits_xof(tail)?,
                    scratch: self.scratch,
                })
            }
        }
        impl Reader for Backend<cshake::$reader<'_, '_>, &mut [u8]> {
            fn read_public(&mut self, output: &mut [u8]) -> Result<(), TupleHashError> {
                self.state
                    .squeeze_public_with_scratch(
                        output,
                        self.scratch,
                        Sha3PublicDeclassification::acknowledge(),
                    )
                    .map_err(TupleHashError::from)
            }
            fn read_secret<'out>(
                &mut self,
                output: &'out mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'out>, TupleHashError> {
                self.state
                    .squeeze_secret(output)
                    .map_err(TupleHashError::from)
            }
            fn public(self, output: Fips202Output<'_>) -> Result<(), TupleHashError> {
                self.state
                    .squeeze_final_bits_public(
                        output,
                        self.scratch,
                        Sha3PublicDeclassification::acknowledge(),
                    )
                    .map_err(TupleHashError::from)
            }
            fn secret<'out>(
                self,
                output: &'out mut [u8],
                valid: u8,
            ) -> Result<HardenedSha3SecretOutput<'out>, TupleHashError> {
                self.state
                    .squeeze_final_bits_secret(output, valid)
                    .map_err(TupleHashError::from)
            }
        }
    };
}
port!(Cshake128, Cshake128Reader);
port!(Cshake256, Cshake256Reader);
