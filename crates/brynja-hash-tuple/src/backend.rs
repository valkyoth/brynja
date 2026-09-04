use brynja_hash_sha3::{
    Fips202BitString, Fips202Output, HardenedCshake128, HardenedCshake128Reader, HardenedCshake256,
    HardenedCshake256Reader, HardenedSha3Error, HardenedSha3SecretOutput,
    Sha3PublicDeclassification,
};

pub(crate) enum Backend {
    Strength128(HardenedCshake128),
    Strength256(HardenedCshake256),
}

pub(crate) enum BackendReader {
    Strength128(HardenedCshake128Reader),
    Strength256(HardenedCshake256Reader),
}

impl Backend {
    pub(crate) fn new(
        strength: u16,
        customization: Fips202BitString<'_>,
    ) -> Result<Self, HardenedSha3Error> {
        let name = Fips202BitString::new(b"TupleHash", 8)
            .map_err(|_| HardenedSha3Error::MessageTooLong)?;
        match strength {
            128 => HardenedCshake128::new_bits(name, customization).map(Self::Strength128),
            _ => HardenedCshake256::new_bits(name, customization).map(Self::Strength256),
        }
    }

    pub(crate) fn check_additional_bits(&self, bits: u128) -> Result<(), HardenedSha3Error> {
        match self {
            Self::Strength128(state) => state.check_additional_bits(bits),
            Self::Strength256(state) => state.check_additional_bits(bits),
        }
    }

    pub(crate) fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha3Error> {
        match self {
            Self::Strength128(state) => state.update(input),
            Self::Strength256(state) => state.update(input),
        }
    }

    pub(crate) fn finalize(
        &mut self,
        tail: Option<Fips202BitString<'_>>,
    ) -> Result<BackendReader, HardenedSha3Error> {
        match (self, tail) {
            (Self::Strength128(state), Some(tail)) => state
                .finalize_bits_xof_erasing_source(tail)
                .map(BackendReader::Strength128),
            (Self::Strength128(state), None) => state
                .finalize_xof_erasing_source()
                .map(BackendReader::Strength128),
            (Self::Strength256(state), Some(tail)) => state
                .finalize_bits_xof_erasing_source(tail)
                .map(BackendReader::Strength256),
            (Self::Strength256(state), None) => state
                .finalize_xof_erasing_source()
                .map(BackendReader::Strength256),
        }
    }

    pub(crate) fn wipe(&mut self) {
        match self {
            Self::Strength128(state) => state.wipe_in_place(),
            Self::Strength256(state) => state.wipe_in_place(),
        }
    }
}

impl BackendReader {
    pub(crate) fn squeeze_public(&mut self, output: &mut [u8]) -> Result<(), HardenedSha3Error> {
        match self {
            Self::Strength128(reader) => {
                reader.squeeze_public(output, Sha3PublicDeclassification::acknowledge())
            }
            Self::Strength256(reader) => {
                reader.squeeze_public(output, Sha3PublicDeclassification::acknowledge())
            }
        }
    }

    pub(crate) fn squeeze_secret<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<HardenedSha3SecretOutput<'a>, HardenedSha3Error> {
        match self {
            Self::Strength128(reader) => reader.squeeze_secret(output),
            Self::Strength256(reader) => reader.squeeze_secret(output),
        }
    }

    pub(crate) fn squeeze_final_public(
        self,
        output: Fips202Output<'_>,
    ) -> Result<(), HardenedSha3Error> {
        match self {
            Self::Strength128(reader) => {
                reader.squeeze_final_bits_public(output, Sha3PublicDeclassification::acknowledge())
            }
            Self::Strength256(reader) => {
                reader.squeeze_final_bits_public(output, Sha3PublicDeclassification::acknowledge())
            }
        }
    }

    pub(crate) fn squeeze_final_secret<'a>(
        self,
        output: Fips202Output<'a>,
    ) -> Result<HardenedSha3SecretOutput<'a>, HardenedSha3Error> {
        match self {
            Self::Strength128(reader) => reader.squeeze_final_bits_secret(output),
            Self::Strength256(reader) => reader.squeeze_final_bits_secret(output),
        }
    }
}
