use super::super::backend::{Reader, State};
use super::{Fips202BitString, KmacError, cshake};
use crate::Fips202Output;
use brynja_hash_sha3::{HardenedSha3SecretOutput, Sha3PublicDeclassification};

// Both fields borrow caller storage; finalization never moves initialized
// sponge, CPU scratch or output staging. Outer scope guards cover forgotten handles.
pub(super) struct Backend<S, B> {
    pub(super) state: S,
    pub(super) scratch: B,
}
macro_rules! port {
    ($state:ident, $reader:ident) => {
        impl<'s, 'a> State for Backend<cshake::$state<'s, 'a>, &'s mut [u8]> {
            type Reader = Backend<cshake::$reader<'s, 'a>, &'s mut [u8]>;
            fn update(&mut self, bytes: &[u8]) -> Result<(), KmacError> {
                self.state.update(bytes).map_err(KmacError::from)
            }
            fn finish(self, input: Fips202BitString<'_>) -> Result<Self::Reader, KmacError> {
                Ok(Backend {
                    state: self.state.finalize_bits_xof(input)?,
                    scratch: self.scratch,
                })
            }
        }
        impl Reader for Backend<cshake::$reader<'_, '_>, &mut [u8]> {
            fn public(&mut self, output: &mut [u8]) -> Result<(), KmacError> {
                self.state
                    .squeeze_public_with_scratch(
                        output,
                        self.scratch,
                        Sha3PublicDeclassification::acknowledge(),
                    )
                    .map_err(KmacError::from)
            }
            fn secret<'o>(
                &mut self,
                output: &'o mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'o>, KmacError> {
                self.state.squeeze_secret(output).map_err(KmacError::from)
            }
            fn final_secret<'o>(
                self,
                output: &'o mut [u8],
                valid: u8,
            ) -> Result<HardenedSha3SecretOutput<'o>, KmacError> {
                self.state
                    .squeeze_final_bits_secret(output, valid)
                    .map_err(KmacError::from)
            }
            fn final_public(self, output: Fips202Output<'_>) -> Result<(), KmacError> {
                self.state
                    .squeeze_final_bits_public(
                        output,
                        self.scratch,
                        Sha3PublicDeclassification::acknowledge(),
                    )
                    .map_err(KmacError::from)
            }
        }
    };
}
port!(Cshake128, Cshake128Reader);
port!(Cshake256, Cshake256Reader);
