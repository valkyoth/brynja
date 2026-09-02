use brynja_hash_core::{FixedOutput, Update};

use crate::{BitString, Sha256Digest, Sha256Error, bit_input, compress::compress};

#[cfg(feature = "cpu")]
use brynja_crypto_cpu::{Sha256BackendError, Sha256BackendSession};

const BLOCK_BYTES: usize = 64;
const LENGTH_FIELD_BYTES: usize = 8;
const FINAL_BLOCK_PREFIX_BYTES: usize = BLOCK_BYTES - LENGTH_FIELD_BYTES;
pub(crate) const INITIAL_STATE: [u32; 8] = [
    0x6a09_e667,
    0xbb67_ae85,
    0x3c6e_f372,
    0xa54f_f53a,
    0x510e_527f,
    0x9b05_688c,
    0x1f83_d9ab,
    0x5be0_cd19,
];

/// Portable streaming SHA-256 state.
///
/// Finalization consumes the state. This type intentionally does not implement
/// `Clone`, `Copy`, `Debug`, or formatting traits. SHA-256 accepts byte strings
/// whose bit length is less than 2^64.
pub struct Sha256 {
    state: [u32; 8],
    buffer: [u8; BLOCK_BYTES],
    buffer_len: usize,
    message_bytes: u64,
}

impl Sha256 {
    /// Maximum arbitrary-bit message length admitted by FIPS 180-4.
    pub const MAX_MESSAGE_BITS: u64 = u64::MAX;

    /// Maximum byte-oriented message length admitted by FIPS 180-4.
    pub const MAX_MESSAGE_BYTES: u64 = u64::MAX / 8;

    /// Creates an empty portable SHA-256 state.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            state: INITIAL_STATE,
            buffer: [0; BLOCK_BYTES],
            buffer_len: 0,
            message_bytes: 0,
        }
    }

    /// Returns the number of message bytes accepted so far.
    #[must_use]
    pub const fn message_bytes(&self) -> u64 {
        self.message_bytes
    }

    /// Returns the byte-aligned number of message bits accepted so far.
    #[must_use]
    pub const fn message_bits(&self) -> u64 {
        self.message_bytes.wrapping_mul(8)
    }

    /// Checks whether an update of `additional_bytes` would fit the SHA-256
    /// message-length domain without changing this state.
    ///
    /// This accepts a `u64` count so callers can preflight file or stream
    /// metadata even when that size cannot be represented by one in-memory
    /// slice. A later [`Self::update`] still performs the same check against
    /// the actual slice length before changing observable state.
    pub fn check_additional_bytes(&self, additional_bytes: u64) -> Result<(), Sha256Error> {
        checked_message_length(self.message_bytes, additional_bytes).map(|_| ())
    }

    /// Checks an exact bit count without changing this state.
    pub fn check_additional_bits(&self, additional_bits: u64) -> Result<(), Sha256Error> {
        bit_input::checked_bit_length_u64(self.message_bytes, additional_bits)
            .map(|_| ())
            .map_err(|_| Sha256Error::MessageTooLong)
    }

    /// Absorbs all input or rejects it before changing the state.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Sha256Error> {
        self.update_portable(input)
    }

    #[cfg(feature = "cpu")]
    /// Absorbs all input through one tested accelerated backend.
    ///
    /// Length and backend health are checked before observable state changes.
    pub fn update_with_backend(
        &mut self,
        input: &[u8],
        backend: &Sha256BackendSession,
    ) -> Result<(), Sha256AcceleratedError> {
        backend
            .ensure_healthy()
            .map_err(Sha256AcceleratedError::from_backend)?;
        self.update_inner(input, |state, block| {
            backend
                .compress(state, block)
                .map_err(Sha256AcceleratedError::from_backend)
        })
        .map_err(|error| match error {
            UpdateInnerError::MessageTooLong => Sha256AcceleratedError::MessageTooLong,
            UpdateInnerError::Compression(error) => error,
        })
    }

    fn update_portable(&mut self, input: &[u8]) -> Result<(), Sha256Error> {
        self.update_inner(input, |state, block| {
            compress(state, block);
            Ok::<(), core::convert::Infallible>(())
        })
        .map_err(|error| match error {
            UpdateInnerError::MessageTooLong => Sha256Error::MessageTooLong,
            UpdateInnerError::Compression(never) => match never {},
        })
    }

    fn update_inner<E, F>(
        &mut self,
        input: &[u8],
        mut compress_block: F,
    ) -> Result<(), UpdateInnerError<E>>
    where
        F: FnMut(&mut [u32; 8], &[u8; BLOCK_BYTES]) -> Result<(), E>,
    {
        let additional =
            u64::try_from(input.len()).map_err(|_| UpdateInnerError::MessageTooLong)?;
        let new_length = checked_message_length(self.message_bytes, additional)
            .map_err(|_| UpdateInnerError::MessageTooLong)?;
        let mut input = input.iter();

        if self.buffer_len != 0 {
            let needed = BLOCK_BYTES.saturating_sub(self.buffer_len);
            let mut copied = 0_usize;
            for (slot, byte) in self
                .buffer
                .iter_mut()
                .skip(self.buffer_len)
                .take(needed)
                .zip(input.by_ref())
            {
                *slot = *byte;
                copied = copied.saturating_add(1);
            }
            self.buffer_len = self.buffer_len.saturating_add(copied);
            if self.buffer_len == BLOCK_BYTES {
                compress_block(&mut self.state, &self.buffer)
                    .map_err(UpdateInnerError::Compression)?;
                self.buffer.fill(0);
                self.buffer_len = 0;
            } else {
                self.message_bytes = new_length;
                return Ok(());
            }
        }

        let mut blocks = input.as_slice().chunks_exact(BLOCK_BYTES);
        for bytes in blocks.by_ref() {
            let mut block = [0_u8; BLOCK_BYTES];
            for (target, byte) in block.iter_mut().zip(bytes.iter()) {
                *target = *byte;
            }
            compress_block(&mut self.state, &block).map_err(UpdateInnerError::Compression)?;
        }
        let remainder = blocks.remainder();
        for (target, byte) in self.buffer.iter_mut().zip(remainder.iter()) {
            *target = *byte;
        }
        self.buffer_len = remainder.len();
        self.message_bytes = new_length;
        Ok(())
    }

    /// Consumes the state and returns the exact SHA-256 digest.
    #[must_use]
    pub fn finalize(self) -> Sha256Digest {
        let message_bits = self.message_bits();
        match self.finalize_inner(None, message_bits, |state, block| {
            compress(state, block);
            Ok::<(), core::convert::Infallible>(())
        }) {
            Ok(digest) => digest,
            Err(never) => match never {},
        }
    }

    /// Consumes the state after absorbing one final canonical bit string.
    ///
    /// Complete bytes may be supplied through [`Self::update`]. A partial byte
    /// can only enter through this consuming operation, so another update or
    /// second tail is structurally impossible.
    ///
    /// ```compile_fail
    /// use brynja_hash_sha2::{BitString, Sha256};
    ///
    /// let mut state = Sha256::new();
    /// let tail = BitString::new(&[0x80], 1).ok().unwrap();
    /// let _digest = state.finalize_bits(tail);
    /// let _too_late = state.update(b"after the tail");
    /// ```
    pub fn finalize_bits(mut self, input: BitString<'_>) -> Result<Sha256Digest, Sha256Error> {
        let additional_bits =
            u64::try_from(input.bit_len()).map_err(|_| Sha256Error::MessageTooLong)?;
        let message_bits = bit_input::checked_bit_length_u64(self.message_bytes, additional_bits)
            .map_err(|_| Sha256Error::MessageTooLong)?;
        let (complete, partial) = input.split();
        self.update_portable(complete)?;
        match self.finalize_inner(partial, message_bits, |state, block| {
            compress(state, block);
            Ok::<(), core::convert::Infallible>(())
        }) {
            Ok(digest) => Ok(digest),
            Err(never) => match never {},
        }
    }

    #[cfg(feature = "cpu")]
    /// Consumes the state and finalizes through one tested backend.
    pub fn finalize_with_backend(
        self,
        backend: &Sha256BackendSession,
    ) -> Result<Sha256Digest, Sha256AcceleratedError> {
        backend
            .ensure_healthy()
            .map_err(Sha256AcceleratedError::from_backend)?;
        let message_bits = self.message_bits();
        self.finalize_inner(None, message_bits, |state, block| {
            backend
                .compress(state, block)
                .map_err(Sha256AcceleratedError::from_backend)
        })
    }

    #[cfg(feature = "cpu")]
    /// Consumes the state after a final bit string through one tested backend.
    pub fn finalize_bits_with_backend(
        mut self,
        input: BitString<'_>,
        backend: &Sha256BackendSession,
    ) -> Result<Sha256Digest, Sha256AcceleratedError> {
        let additional_bits =
            u64::try_from(input.bit_len()).map_err(|_| Sha256AcceleratedError::MessageTooLong)?;
        let message_bits = bit_input::checked_bit_length_u64(self.message_bytes, additional_bits)
            .map_err(|_| Sha256AcceleratedError::MessageTooLong)?;
        let (complete, partial) = input.split();
        self.update_with_backend(complete, backend)?;
        backend
            .ensure_healthy()
            .map_err(Sha256AcceleratedError::from_backend)?;
        self.finalize_inner(partial, message_bits, |state, block| {
            backend
                .compress(state, block)
                .map_err(Sha256AcceleratedError::from_backend)
        })
    }

    fn finalize_inner<E, F>(
        mut self,
        partial: Option<(u8, u8)>,
        message_bits: u64,
        mut compress_block: F,
    ) -> Result<Sha256Digest, E>
    where
        F: FnMut(&mut [u32; 8], &[u8; BLOCK_BYTES]) -> Result<(), E>,
    {
        bit_input::begin_padding(&mut self.buffer, self.buffer_len, partial);
        if padding_block_count(self.buffer_len) == 2 {
            compress_block(&mut self.state, &self.buffer)?;
            self.buffer.fill(0);
        }
        for (target, byte) in self
            .buffer
            .iter_mut()
            .skip(FINAL_BLOCK_PREFIX_BYTES)
            .zip(message_bits.to_be_bytes())
        {
            *target = byte;
        }
        compress_block(&mut self.state, &self.buffer)?;

        let mut output = [0_u8; Sha256Digest::LENGTH];
        for (bytes, word) in output.chunks_exact_mut(4).zip(self.state.iter()) {
            if let [first, second, third, fourth] = bytes {
                [*first, *second, *third, *fourth] = word.to_be_bytes();
            }
        }
        Ok(Sha256Digest::from_bytes(output))
    }
}

enum UpdateInnerError<E> {
    MessageTooLong,
    Compression(E),
}

/// Closed failure from an explicitly accelerated SHA-256 operation.
#[cfg(feature = "cpu")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Sha256AcceleratedError {
    /// The input exceeds SHA-256's byte-oriented message domain.
    MessageTooLong,
    /// The selected backend belongs to another architecture.
    WrongArchitecture,
    /// The implementation exists but lacks native admission evidence.
    BackendNotAdmitted,
    /// The caller-owned backend session is permanently quarantined.
    BackendQuarantined,
    /// The backend returned a newer closed failure unknown to this version.
    BackendUnavailable,
}

#[cfg(feature = "cpu")]
impl Sha256AcceleratedError {
    fn from_backend(error: Sha256BackendError) -> Self {
        match error {
            Sha256BackendError::WrongArchitecture => Self::WrongArchitecture,
            Sha256BackendError::NotAdmitted => Self::BackendNotAdmitted,
            Sha256BackendError::Quarantined => Self::BackendQuarantined,
            _ => Self::BackendUnavailable,
        }
    }
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Update for Sha256 {
    type Error = Sha256Error;

    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error> {
        Self::update(self, input)
    }
}

impl FixedOutput for Sha256 {
    type Output = Sha256Digest;

    fn finalize(self) -> Self::Output {
        Self::finalize(self)
    }
}

pub(crate) fn checked_message_length(current: u64, additional: u64) -> Result<u64, Sha256Error> {
    current
        .checked_add(additional)
        .filter(|length| *length <= Sha256::MAX_MESSAGE_BYTES)
        .ok_or(Sha256Error::MessageTooLong)
}

pub(crate) const fn padding_block_count(buffer_len: usize) -> usize {
    if buffer_len < FINAL_BLOCK_PREFIX_BYTES {
        1
    } else {
        2
    }
}
