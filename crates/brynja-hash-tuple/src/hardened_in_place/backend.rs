use crate::{Fips202BitString, Fips202Output, TupleHashError};
use brynja_hash_sha3::{
    HardenedSha3SecretOutput, Sha3PublicDeclassification, hardened_in_place as api,
};

// Only borrowed scoped cSHAKE handles implement this private interface. Moving
// these adapters never transfers an inline sponge or populated metadata owner.
pub(super) trait State {
    type Reader: Reader;
    fn update(&mut self, input: &[u8]) -> Result<(), TupleHashError>;
    fn finish(self, tail: Fips202BitString<'_>) -> Result<Self::Reader, TupleHashError>;
}
pub(super) trait Reader {
    fn read_public(&mut self, output: &mut [u8]) -> Result<(), TupleHashError>;
    fn read_secret<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<HardenedSha3SecretOutput<'out>, TupleHashError>;
    fn public(self, output: Fips202Output<'_>) -> Result<(), TupleHashError>;
    fn secret<'out>(
        self,
        output: Fips202Output<'out>,
    ) -> Result<HardenedSha3SecretOutput<'out>, TupleHashError>;
}
macro_rules! port {
    ($state:ident, $reader:ident) => {
        impl<'scope> State for api::$state<'scope> {
            type Reader = api::$reader<'scope>;
            fn update(&mut self, input: &[u8]) -> Result<(), TupleHashError> {
                Self::update(self, input).map_err(TupleHashError::from)
            }
            fn finish(self, tail: Fips202BitString<'_>) -> Result<Self::Reader, TupleHashError> {
                self.finalize_bits_xof(tail).map_err(TupleHashError::from)
            }
        }
        impl Reader for api::$reader<'_> {
            fn read_public(&mut self, output: &mut [u8]) -> Result<(), TupleHashError> {
                self.squeeze_public(output, Sha3PublicDeclassification::acknowledge())
                    .map_err(TupleHashError::from)
            }
            fn read_secret<'out>(
                &mut self,
                output: &'out mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'out>, TupleHashError> {
                self.squeeze_secret(output).map_err(TupleHashError::from)
            }
            fn public(self, output: Fips202Output<'_>) -> Result<(), TupleHashError> {
                self.squeeze_final_bits_public(output, Sha3PublicDeclassification::acknowledge())
                    .map_err(TupleHashError::from)
            }
            fn secret<'out>(
                self,
                output: Fips202Output<'out>,
            ) -> Result<HardenedSha3SecretOutput<'out>, TupleHashError> {
                self.squeeze_final_bits_secret(output)
                    .map_err(TupleHashError::from)
            }
        }
    };
}
port!(Cshake128, Cshake128Reader);
port!(Cshake256, Cshake256Reader);
