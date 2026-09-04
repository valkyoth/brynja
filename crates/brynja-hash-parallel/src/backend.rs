use brynja_hash_sha3::{
    Fips202BitString, Fips202Output, HardenedCshake128, HardenedCshake256, HardenedSha3Error,
    HardenedSha3SecretOutput, Sha3PublicDeclassification,
};

pub(crate) const LEAF_128_BYTES: usize = 32;
pub(crate) const LEAF_256_BYTES: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Strength {
    Bits128,
    Bits256,
}

pub(crate) enum Backend {
    Bits128(HardenedCshake128),
    Bits256(HardenedCshake256),
}

pub(crate) struct BackendReader<'a> {
    backend: &'a mut Backend,
}

impl Backend {
    pub(crate) fn outer(
        strength: Strength,
        customization: Fips202BitString<'_>,
    ) -> Result<Self, HardenedSha3Error> {
        let name = Fips202BitString::new(b"ParallelHash", 8)
            .map_err(|_| HardenedSha3Error::MessageTooLong)?;
        match strength {
            Strength::Bits128 => {
                HardenedCshake128::new_bits(name, customization).map(Self::Bits128)
            }
            Strength::Bits256 => {
                HardenedCshake256::new_bits(name, customization).map(Self::Bits256)
            }
        }
    }

    pub(crate) fn update(&mut self, input: &[u8]) -> Result<(), HardenedSha3Error> {
        match self {
            Self::Bits128(state) => state.update(input),
            Self::Bits256(state) => state.update(input),
        }
    }

    pub(crate) fn finalize_in_place(&mut self) -> Result<BackendReader<'_>, HardenedSha3Error> {
        match self {
            Self::Bits128(state) => state.enter_squeezing_in_place(None)?,
            Self::Bits256(state) => state.enter_squeezing_in_place(None)?,
        }
        Ok(BackendReader { backend: self })
    }

    pub(crate) fn wipe(&mut self) {
        match self {
            Self::Bits128(state) => state.wipe_in_place(),
            Self::Bits256(state) => state.wipe_in_place(),
        }
    }
}

impl BackendReader<'_> {
    pub(crate) fn squeeze_public(&mut self, output: &mut [u8]) -> Result<(), HardenedSha3Error> {
        match self.backend {
            Backend::Bits128(state) => {
                state.squeeze_public_in_place(output, Sha3PublicDeclassification::acknowledge())
            }
            Backend::Bits256(state) => {
                state.squeeze_public_in_place(output, Sha3PublicDeclassification::acknowledge())
            }
        }
    }

    pub(crate) fn squeeze_secret<'a>(
        &mut self,
        output: &'a mut [u8],
    ) -> Result<HardenedSha3SecretOutput<'a>, HardenedSha3Error> {
        match self.backend {
            Backend::Bits128(state) => state.squeeze_secret_in_place(output),
            Backend::Bits256(state) => state.squeeze_secret_in_place(output),
        }
    }

    pub(crate) fn squeeze_final_public(
        self,
        output: Fips202Output<'_>,
    ) -> Result<(), HardenedSha3Error> {
        match self.backend {
            Backend::Bits128(state) => state.squeeze_final_bits_public_in_place(
                output,
                Sha3PublicDeclassification::acknowledge(),
            ),
            Backend::Bits256(state) => state.squeeze_final_bits_public_in_place(
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
            Backend::Bits128(state) => state.squeeze_final_bits_secret_in_place(output),
            Backend::Bits256(state) => state.squeeze_final_bits_secret_in_place(output),
        }
    }
}

impl Drop for BackendReader<'_> {
    fn drop(&mut self) {
        self.backend.wipe();
    }
}

pub(crate) fn leaf128<'a>(
    input: Fips202BitString<'_>,
    output: &'a mut [u8; LEAF_128_BYTES],
) -> Result<HardenedSha3SecretOutput<'a>, HardenedSha3Error> {
    let mut state = HardenedCshake128::new(b"", b"")?;
    let (complete, tail) = split(input);
    state.update(complete)?;
    let mut reader = match tail {
        Some(tail) => state.finalize_bits_xof(bit_tail(&tail)?)?,
        None => state.finalize_xof()?,
    };
    reader.squeeze_secret(output)
}

pub(crate) fn leaf256<'a>(
    input: Fips202BitString<'_>,
    output: &'a mut [u8; LEAF_256_BYTES],
) -> Result<HardenedSha3SecretOutput<'a>, HardenedSha3Error> {
    let mut state = HardenedCshake256::new(b"", b"")?;
    let (complete, tail) = split(input);
    state.update(complete)?;
    let mut reader = match tail {
        Some(tail) => state.finalize_bits_xof(bit_tail(&tail)?)?,
        None => state.finalize_xof()?,
    };
    reader.squeeze_secret(output)
}

fn split(input: Fips202BitString<'_>) -> (&[u8], Option<[u8; 2]>) {
    if input.is_byte_aligned() {
        return (input.as_bytes(), None);
    }
    let split = input.as_bytes().len().saturating_sub(1);
    let (complete, tail) = input.as_bytes().split_at(split);
    (
        complete,
        tail.first()
            .copied()
            .map(|byte| [byte, input.valid_bits_in_last_byte()]),
    )
}

fn bit_tail(value: &[u8; 2]) -> Result<Fips202BitString<'_>, HardenedSha3Error> {
    Fips202BitString::new(
        value.get(..1).unwrap_or_default(),
        value.get(1).copied().unwrap_or_default(),
    )
    .map_err(|_| HardenedSha3Error::MessageTooLong)
}
