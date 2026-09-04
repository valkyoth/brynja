use brynja_hash_sha3::{
    Fips202BitString, Fips202Output, HardenedCshake128, HardenedCshake256, HardenedSha3Error,
    HardenedSha3SecretOutput, Sha3PublicDeclassification,
};

pub(crate) enum Backend {
    Strength128(HardenedCshake128),
    Strength256(HardenedCshake256),
}

pub(crate) struct BackendReader<'a> {
    backend: &'a mut Backend,
}

#[derive(Clone, Copy)]
pub(crate) enum BackendStrength {
    Bits128,
    Bits256,
}

impl Backend {
    pub(crate) fn new(
        strength: BackendStrength,
        customization: Fips202BitString<'_>,
    ) -> Result<Self, HardenedSha3Error> {
        let name = Fips202BitString::new(b"TupleHash", 8)
            .map_err(|_| HardenedSha3Error::MessageTooLong)?;
        match strength {
            BackendStrength::Bits128 => {
                HardenedCshake128::new_bits(name, customization).map(Self::Strength128)
            }
            BackendStrength::Bits256 => {
                HardenedCshake256::new_bits(name, customization).map(Self::Strength256)
            }
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

    pub(crate) fn finalize_in_place(
        &mut self,
        tail: Option<Fips202BitString<'_>>,
    ) -> Result<BackendReader<'_>, HardenedSha3Error> {
        match self {
            Self::Strength128(state) => state.enter_squeezing_in_place(tail)?,
            Self::Strength256(state) => state.enter_squeezing_in_place(tail)?,
        }
        Ok(BackendReader { backend: self })
    }

    pub(crate) fn wipe(&mut self) {
        match self {
            Self::Strength128(state) => state.wipe_in_place(),
            Self::Strength256(state) => state.wipe_in_place(),
        }
    }
}

impl BackendReader<'_> {
    pub(crate) fn squeeze_public(&mut self, output: &mut [u8]) -> Result<(), HardenedSha3Error> {
        match self.backend {
            Backend::Strength128(state) => {
                state.squeeze_public_in_place(output, Sha3PublicDeclassification::acknowledge())
            }
            Backend::Strength256(state) => {
                state.squeeze_public_in_place(output, Sha3PublicDeclassification::acknowledge())
            }
        }
    }

    pub(crate) fn squeeze_secret<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<HardenedSha3SecretOutput<'a>, HardenedSha3Error> {
        match self.backend {
            Backend::Strength128(state) => state.squeeze_secret_in_place(output),
            Backend::Strength256(state) => state.squeeze_secret_in_place(output),
        }
    }

    pub(crate) fn squeeze_final_public(
        self,
        output: Fips202Output<'_>,
    ) -> Result<(), HardenedSha3Error> {
        match self.backend {
            Backend::Strength128(state) => state.squeeze_final_bits_public_in_place(
                output,
                Sha3PublicDeclassification::acknowledge(),
            ),
            Backend::Strength256(state) => state.squeeze_final_bits_public_in_place(
                output,
                Sha3PublicDeclassification::acknowledge(),
            ),
        }
    }

    pub(crate) fn squeeze_final_secret<'a>(
        self,
        output: Fips202Output<'a>,
    ) -> Result<HardenedSha3SecretOutput<'a>, HardenedSha3Error> {
        match self.backend {
            Backend::Strength128(state) => state.squeeze_final_bits_secret_in_place(output),
            Backend::Strength256(state) => state.squeeze_final_bits_secret_in_place(output),
        }
    }
}

impl Drop for BackendReader<'_> {
    fn drop(&mut self) {
        self.backend.wipe();
    }
}
