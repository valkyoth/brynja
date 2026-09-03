use brynja_hash_sha3::{
    Fips202BitString, Fips202Output, HardenedCshake128, HardenedCshake128Reader, HardenedCshake256,
    HardenedCshake256Reader, HardenedSha3Error, HardenedSha3SecretOutput,
    Sha3PublicDeclassification,
};

pub(crate) trait CshakeState: Sized {
    type Reader: CshakeReader;

    fn new_kmac(customization: Fips202BitString<'_>) -> Result<Self, HardenedSha3Error>;
    fn check_additional_bytes(&self, additional: u128) -> Result<(), HardenedSha3Error>;
    fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha3Error>;
    fn wipe_in_place(&mut self);
    fn finalize_xof_erasing_source(&mut self) -> Result<Self::Reader, HardenedSha3Error>;
    fn finalize_bits_xof_erasing_source(
        &mut self,
        input: Fips202BitString<'_>,
    ) -> Result<Self::Reader, HardenedSha3Error>;
}

pub(crate) trait CshakeReader: Sized {
    fn output_bytes(&self) -> u128;
    fn check_additional_bytes(&self, additional: u128) -> Result<(), HardenedSha3Error>;
    fn check_additional_bits(&self, additional: u128) -> Result<(), HardenedSha3Error>;
    fn squeeze_public(&mut self, output: &mut [u8]) -> Result<(), HardenedSha3Error>;
    fn squeeze_secret<'output>(
        &mut self,
        output: &'output mut [u8],
    ) -> Result<HardenedSha3SecretOutput<'output>, HardenedSha3Error>;
    fn squeeze_final_bits_public(self, output: Fips202Output<'_>) -> Result<(), HardenedSha3Error>;
    fn squeeze_final_bits_secret<'output>(
        self,
        output: Fips202Output<'output>,
    ) -> Result<HardenedSha3SecretOutput<'output>, HardenedSha3Error>;
}

macro_rules! backend {
    ($state:ty, $reader:ty) => {
        impl CshakeState for $state {
            type Reader = $reader;

            fn new_kmac(customization: Fips202BitString<'_>) -> Result<Self, HardenedSha3Error> {
                let name = Fips202BitString::new(b"KMAC", 8)
                    .map_err(|_| HardenedSha3Error::MessageTooLong)?;
                Self::new_bits(name, customization)
            }

            fn check_additional_bytes(&self, additional: u128) -> Result<(), HardenedSha3Error> {
                Self::check_additional_bytes(self, additional)
            }

            fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha3Error> {
                Self::update(self, input)
            }

            fn wipe_in_place(&mut self) {
                Self::wipe_in_place(self);
            }

            fn finalize_xof_erasing_source(&mut self) -> Result<Self::Reader, HardenedSha3Error> {
                Self::finalize_xof_erasing_source(self)
            }

            fn finalize_bits_xof_erasing_source(
                &mut self,
                input: Fips202BitString<'_>,
            ) -> Result<Self::Reader, HardenedSha3Error> {
                Self::finalize_bits_xof_erasing_source(self, input)
            }
        }

        impl CshakeReader for $reader {
            fn output_bytes(&self) -> u128 {
                Self::output_bytes(self)
            }

            fn check_additional_bytes(&self, additional: u128) -> Result<(), HardenedSha3Error> {
                Self::check_additional_bytes(self, additional)
            }

            fn check_additional_bits(&self, additional: u128) -> Result<(), HardenedSha3Error> {
                Self::check_additional_bits(self, additional)
            }

            fn squeeze_public(&mut self, output: &mut [u8]) -> Result<(), HardenedSha3Error> {
                Self::squeeze_public(self, output, Sha3PublicDeclassification::acknowledge())
            }

            fn squeeze_secret<'output>(
                &mut self,
                output: &'output mut [u8],
            ) -> Result<HardenedSha3SecretOutput<'output>, HardenedSha3Error> {
                Self::squeeze_secret(self, output)
            }

            fn squeeze_final_bits_public(
                self,
                output: Fips202Output<'_>,
            ) -> Result<(), HardenedSha3Error> {
                Self::squeeze_final_bits_public(
                    self,
                    output,
                    Sha3PublicDeclassification::acknowledge(),
                )
            }

            fn squeeze_final_bits_secret<'output>(
                self,
                output: Fips202Output<'output>,
            ) -> Result<HardenedSha3SecretOutput<'output>, HardenedSha3Error> {
                Self::squeeze_final_bits_secret(self, output)
            }
        }
    };
}

backend!(HardenedCshake128, HardenedCshake128Reader);
backend!(HardenedCshake256, HardenedCshake256Reader);
