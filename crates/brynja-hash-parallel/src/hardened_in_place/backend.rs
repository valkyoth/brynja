use crate::{Fips202BitString, Fips202Output, ParallelHashError as Error};
use brynja_hash_sha3::{
    HardenedSha3SecretOutput, Sha3PublicDeclassification, hardened_in_place as api,
};

pub(super) trait State {
    type Reader: Reader;
    fn update(&mut self, input: &[u8]) -> Result<(), Error>;
    fn finish(self) -> Result<Self::Reader, Error>;
    fn leaf<'out>(
        input: Fips202BitString<'_>,
        output: &'out mut [u8; 64],
    ) -> Result<HardenedSha3SecretOutput<'out>, Error>;
}
pub(super) trait Reader {
    fn read_public(&mut self, output: &mut [u8]) -> Result<(), Error>;
    fn read_secret<'out>(
        &mut self,
        output: &'out mut [u8],
    ) -> Result<HardenedSha3SecretOutput<'out>, Error>;
    fn public(self, output: Fips202Output<'_>) -> Result<(), Error>;
    fn secret<'out>(
        self,
        output: &'out mut [u8],
        valid: u8,
    ) -> Result<HardenedSha3SecretOutput<'out>, Error>;
}
macro_rules! port {
    ($state:ident, $reader:ident, $leaf:ident, $size:expr) => {
        impl<'scope> State for api::$state<'scope> {
            type Reader = api::$reader<'scope>;
            fn update(&mut self, input: &[u8]) -> Result<(), Error> {
                Self::update(self, input).map_err(Error::from)
            }
            fn finish(self) -> Result<Self::Reader, Error> {
                self.finalize_xof().map_err(Error::from)
            }
            fn leaf<'out>(
                input: Fips202BitString<'_>,
                output: &'out mut [u8; 64],
            ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
                let bytes = output.get_mut(..$size).ok_or(Error::SecretMemory)?;
                crate::backend::$leaf(input, bytes.try_into().map_err(|_| Error::SecretMemory)?)
                    .map_err(Error::from)
            }
        }
        impl Reader for api::$reader<'_> {
            fn read_public(&mut self, output: &mut [u8]) -> Result<(), Error> {
                self.squeeze_public(output, Sha3PublicDeclassification::acknowledge())
                    .map_err(Error::from)
            }
            fn read_secret<'out>(
                &mut self,
                output: &'out mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
                self.squeeze_secret(output).map_err(Error::from)
            }
            fn public(self, output: Fips202Output<'_>) -> Result<(), Error> {
                self.squeeze_final_bits_public(output, Sha3PublicDeclassification::acknowledge())
                    .map_err(Error::from)
            }
            fn secret<'out>(
                self,
                output: &'out mut [u8],
                valid: u8,
            ) -> Result<HardenedSha3SecretOutput<'out>, Error> {
                self.squeeze_final_bits_secret(
                    Fips202Output::new(output, valid).map_err(|_| Error::InvalidBitString)?,
                )
                .map_err(Error::from)
            }
        }
    };
}
port!(Cshake128, Cshake128Reader, leaf128, 32);
port!(Cshake256, Cshake256Reader, leaf256, 64);
