use brynja_hash_core::{ExtendableOutput, Update, XofReader};

use crate::{
    Fips202BitString, Fips202Output, Shake128Error,
    sponge::{Sponge, Squeezer},
};

const RATE_BYTES: usize = 168;

/// Portable streaming SHAKE128 absorbing state.
///
/// Finalization consumes this state and returns a [`Shake128Reader`], making
/// absorption after squeezing structurally impossible. Ordinary unkeyed state
/// is not promised to be erased after use.
pub struct Shake128(Sponge<RATE_BYTES>);

impl Shake128 {
    /// Maximum input byte count representable by this implementation.
    pub const MAX_MESSAGE_BYTES: u128 = Sponge::<RATE_BYTES>::MAX_MESSAGE_BYTES;

    /// Creates an empty portable SHAKE128 absorbing state.
    #[must_use]
    pub const fn new() -> Self {
        Self(Sponge::new())
    }

    /// Returns the number of message bytes accepted so far.
    #[must_use]
    pub const fn message_bytes(&self) -> u128 {
        self.0.message_bytes()
    }

    /// Checks an update length without changing this state.
    pub fn check_additional_bytes(&self, additional: u128) -> Result<(), Shake128Error> {
        self.0
            .check_additional_bytes(additional)
            .map_err(|()| Shake128Error::MessageTooLong)
    }

    /// Checks an exact bit count without changing this state.
    pub fn check_additional_bits(&self, additional: u128) -> Result<(), Shake128Error> {
        self.0
            .check_additional_bits(additional)
            .map_err(|()| Shake128Error::MessageTooLong)
    }

    /// Absorbs all input or rejects it before changing observable state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Shake128Error> {
        self.0
            .update(input)
            .map_err(|()| Shake128Error::MessageTooLong)
    }

    /// Consumes the absorbing state and returns its incremental XOF reader.
    #[must_use]
    pub fn finalize_xof(self) -> Shake128Reader {
        Shake128Reader(self.0.finalize_xof())
    }

    /// Consumes the state after absorbing one final canonical FIPS 202 bit string.
    pub fn finalize_bits_xof(
        mut self,
        input: Fips202BitString<'_>,
    ) -> Result<Shake128Reader, Shake128Error> {
        let bits = u128::try_from(input.bit_len()).map_err(|_| Shake128Error::MessageTooLong)?;
        self.0
            .check_additional_bits(bits)
            .map_err(|()| Shake128Error::MessageTooLong)?;
        let (complete, partial) = input.split();
        self.update(complete)?;
        Ok(Shake128Reader(self.0.finalize_bits_xof(partial)))
    }
}

impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Shake128 {
    type Error = Shake128Error;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Self::update(self, input)
    }
}

impl ExtendableOutput for Shake128 {
    type Reader = Shake128Reader;

    fn finalize_xof(self) -> Self::Reader {
        Self::finalize_xof(self)
    }
}

/// Incremental SHAKE128 output reader.
///
/// Consecutive calls continue the same output stream. A zero-length call is a
/// valid no-op. The reader intentionally is not cloneable or copyable.
pub struct Shake128Reader(Squeezer<RATE_BYTES>);

impl Shake128Reader {
    /// Maximum output byte count representable by this implementation.
    pub const MAX_OUTPUT_BYTES: u128 = Squeezer::<RATE_BYTES>::MAX_OUTPUT_BYTES;
    /// Returns the number of bytes emitted so far.
    #[must_use]
    pub const fn output_bytes(&self) -> u128 {
        self.0.output_bytes()
    }

    /// Checks an output length without changing this reader.
    pub fn check_additional_bytes(&self, additional: u128) -> Result<(), Shake128Error> {
        self.0
            .check_additional_bytes(additional)
            .map_err(|()| Shake128Error::OutputTooLong)
    }

    /// Checks an exact output bit count without changing this reader.
    pub fn check_additional_bits(&self, additional: u128) -> Result<(), Shake128Error> {
        self.0
            .check_additional_bits(additional)
            .map_err(|()| Shake128Error::OutputTooLong)
    }

    /// Fills all caller-owned output or rejects before changing either side.
    pub fn squeeze(&mut self, output: &mut [u8]) -> Result<(), Shake128Error> {
        self.0
            .squeeze(output)
            .map_err(|()| Shake128Error::OutputTooLong)
    }

    /// Consumes the reader after writing one final canonical bit destination.
    pub fn squeeze_final_bits(self, output: Fips202Output<'_>) -> Result<(), Shake128Error> {
        self.0
            .squeeze_final_bits(output)
            .map_err(|()| Shake128Error::OutputTooLong)
    }
}

impl XofReader for Shake128Reader {
    type Error = Shake128Error;

    fn squeeze(&mut self, output: &mut [u8]) -> Result<(), Self::Error> {
        Self::squeeze(self, output)
    }
}
