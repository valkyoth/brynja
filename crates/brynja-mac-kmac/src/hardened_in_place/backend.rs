use crate::{Fips202BitString, Fips202Output, KmacError, packer::Absorb};
use brynja_hash_sha3::{
    HardenedSha3SecretOutput, Sha3PublicDeclassification, hardened_in_place as api,
};

pub(super) trait State {
    type Reader: Reader;
    fn update(&mut self, bytes: &[u8]) -> Result<(), KmacError>;
    fn finish(self, input: Fips202BitString<'_>) -> Result<Self::Reader, KmacError>;
}
pub(super) trait Reader: Sized {
    fn public(&mut self, output: &mut [u8]) -> Result<(), KmacError>;
    fn secret<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<HardenedSha3SecretOutput<'out>, KmacError>;
    fn final_secret<'out>(
        self,
        output: Fips202Output<'out>,
    ) -> Result<HardenedSha3SecretOutput<'out>, KmacError>;
    fn final_public(self, output: Fips202Output<'_>) -> Result<(), KmacError>;
}

// S contains only the scoped cSHAKE reference and lifecycle flag, never an
// inline secret owner. Taking it transfers that borrow into the reader.
pub(super) struct Borrowed<S: State>(pub(super) Option<S>);
impl<S: State> Absorb for Borrowed<S> {
    fn absorb(&mut self, input: &[u8]) -> Result<(), KmacError> {
        self.0
            .as_mut()
            .ok_or(KmacError::StateConsumed)?
            .update(input)
    }
}
macro_rules! port {
    ($state:ident, $reader:ident) => {
        impl<'scope> State for api::$state<'scope> {
            type Reader = api::$reader<'scope>;
            fn update(&mut self, bytes: &[u8]) -> Result<(), KmacError> {
                Self::update(self, bytes).map_err(KmacError::from)
            }
            fn finish(self, input: Fips202BitString<'_>) -> Result<Self::Reader, KmacError> {
                self.finalize_bits_xof(input).map_err(KmacError::from)
            }
        }
        impl Reader for api::$reader<'_> {
            fn public(&mut self, output: &mut [u8]) -> Result<(), KmacError> {
                self.squeeze_public(output, Sha3PublicDeclassification::acknowledge())
                    .map_err(KmacError::from)
            }
            fn secret<'out>(
                &mut self,
                output: &'out mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'out>, KmacError> {
                self.squeeze_secret(output).map_err(KmacError::from)
            }
            fn final_secret<'out>(
                self,
                output: Fips202Output<'out>,
            ) -> Result<HardenedSha3SecretOutput<'out>, KmacError> {
                self.squeeze_final_bits_secret(output)
                    .map_err(KmacError::from)
            }
            fn final_public(self, output: Fips202Output<'_>) -> Result<(), KmacError> {
                self.squeeze_final_bits_public(output, Sha3PublicDeclassification::acknowledge())
                    .map_err(KmacError::from)
            }
        }
    };
}
port!(Cshake128, Cshake128Reader);
port!(Cshake256, Cshake256Reader);
