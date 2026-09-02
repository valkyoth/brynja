use crate::{BitString, bit_input, compress64::compress};

#[cfg(feature = "cpu")]
use brynja_crypto_cpu::{Sha512BackendError, Sha512BackendSession};

const BLOCK_BYTES: usize = 128;
const LENGTH_FIELD_BYTES: usize = 16;
const FINAL_BLOCK_PREFIX_BYTES: usize = BLOCK_BYTES - LENGTH_FIELD_BYTES;

pub(crate) const MAX_MESSAGE_BYTES: u128 = u128::MAX / 8;
pub(crate) const MAX_MESSAGE_BITS: u128 = u128::MAX;

pub(crate) struct Sha512State {
    state: [u64; 8],
    buffer: [u8; BLOCK_BYTES],
    buffer_len: usize,
    message_bytes: u128,
}

impl Sha512State {
    pub(crate) const fn new(initial_state: [u64; 8]) -> Self {
        Self {
            state: initial_state,
            buffer: [0; BLOCK_BYTES],
            buffer_len: 0,
            message_bytes: 0,
        }
    }

    pub(crate) const fn message_bytes(&self) -> u128 {
        self.message_bytes
    }

    pub(crate) const fn message_bits(&self) -> u128 {
        self.message_bytes.wrapping_mul(8)
    }

    pub(crate) fn check_additional_bytes(
        &self,
        additional_bytes: u128,
    ) -> Result<(), MessageTooLong> {
        checked_message_length(self.message_bytes, additional_bytes).map(|_| ())
    }

    pub(crate) fn check_additional_bits(
        &self,
        additional_bits: u128,
    ) -> Result<(), MessageTooLong> {
        bit_input::checked_bit_length_u128(self.message_bytes, additional_bits)
            .map(|_| ())
            .map_err(|_| MessageTooLong)
    }

    pub(crate) fn update(&mut self, input: &[u8]) -> Result<(), MessageTooLong> {
        self.update_inner(input, |state, block| {
            compress(state, block);
            Ok::<(), core::convert::Infallible>(())
        })
        .map_err(|error| match error {
            UpdateInnerError::MessageTooLong => MessageTooLong,
            UpdateInnerError::Compression(never) => match never {},
        })
    }

    #[cfg(feature = "cpu")]
    pub(crate) fn update_with_backend(
        &mut self,
        input: &[u8],
        backend: &Sha512BackendSession,
    ) -> Result<(), Sha512AcceleratedError> {
        backend
            .ensure_healthy()
            .map_err(Sha512AcceleratedError::from_backend)?;
        self.update_inner(input, |state, block| {
            backend
                .compress(state, block)
                .map_err(Sha512AcceleratedError::from_backend)
        })
        .map_err(|error| match error {
            UpdateInnerError::MessageTooLong => Sha512AcceleratedError::MessageTooLong,
            UpdateInnerError::Compression(error) => error,
        })
    }

    fn update_inner<E, F>(
        &mut self,
        input: &[u8],
        mut compress_block: F,
    ) -> Result<(), UpdateInnerError<E>>
    where
        F: FnMut(&mut [u64; 8], &[u8; BLOCK_BYTES]) -> Result<(), E>,
    {
        let additional = input.len() as u128;
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

    pub(crate) fn finalize(self) -> [u64; 8] {
        let message_bits = self.message_bits();
        match self.finalize_inner(None, message_bits, |state, block| {
            compress(state, block);
            Ok::<(), core::convert::Infallible>(())
        }) {
            Ok(state) => state,
            Err(never) => match never {},
        }
    }

    pub(crate) fn finalize_bits(
        mut self,
        input: BitString<'_>,
    ) -> Result<[u64; 8], MessageTooLong> {
        let additional_bits = u128::try_from(input.bit_len()).map_err(|_| MessageTooLong)?;
        let message_bits = bit_input::checked_bit_length_u128(self.message_bytes, additional_bits)
            .map_err(|_| MessageTooLong)?;
        let (complete, partial) = input.split();
        self.update(complete)?;
        match self.finalize_inner(partial, message_bits, |state, block| {
            compress(state, block);
            Ok::<(), core::convert::Infallible>(())
        }) {
            Ok(state) => Ok(state),
            Err(never) => match never {},
        }
    }

    #[cfg(feature = "cpu")]
    pub(crate) fn finalize_with_backend(
        self,
        backend: &Sha512BackendSession,
    ) -> Result<[u64; 8], Sha512AcceleratedError> {
        backend
            .ensure_healthy()
            .map_err(Sha512AcceleratedError::from_backend)?;
        let message_bits = self.message_bits();
        self.finalize_inner(None, message_bits, |state, block| {
            backend
                .compress(state, block)
                .map_err(Sha512AcceleratedError::from_backend)
        })
    }

    #[cfg(feature = "cpu")]
    pub(crate) fn finalize_bits_with_backend(
        mut self,
        input: BitString<'_>,
        backend: &Sha512BackendSession,
    ) -> Result<[u64; 8], Sha512AcceleratedError> {
        let additional_bits =
            u128::try_from(input.bit_len()).map_err(|_| Sha512AcceleratedError::MessageTooLong)?;
        let message_bits = bit_input::checked_bit_length_u128(self.message_bytes, additional_bits)
            .map_err(|_| Sha512AcceleratedError::MessageTooLong)?;
        let (complete, partial) = input.split();
        self.update_with_backend(complete, backend)?;
        backend
            .ensure_healthy()
            .map_err(Sha512AcceleratedError::from_backend)?;
        self.finalize_inner(partial, message_bits, |state, block| {
            backend
                .compress(state, block)
                .map_err(Sha512AcceleratedError::from_backend)
        })
    }

    fn finalize_inner<E, F>(
        mut self,
        partial: Option<(u8, u8)>,
        message_bits: u128,
        mut compress_block: F,
    ) -> Result<[u64; 8], E>
    where
        F: FnMut(&mut [u64; 8], &[u8; BLOCK_BYTES]) -> Result<(), E>,
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
        Ok(self.state)
    }
}

enum UpdateInnerError<E> {
    MessageTooLong,
    Compression(E),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct MessageTooLong;

/// Closed failure from an explicitly accelerated SHA-512-family operation.
#[cfg(feature = "cpu")]
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum Sha512AcceleratedError {
    /// The input exceeds the SHA-512-family byte-oriented message domain.
    MessageTooLong,
    /// The selected backend belongs to another architecture.
    WrongArchitecture,
    /// The implementation exists but lacks native admission evidence.
    BackendNotAdmitted,
    /// The caller-owned backend session is permanently quarantined.
    BackendQuarantined,
    /// A newer backend failure is unknown to this crate version.
    BackendUnavailable,
}

#[cfg(feature = "cpu")]
impl Sha512AcceleratedError {
    fn from_backend(error: Sha512BackendError) -> Self {
        match error {
            Sha512BackendError::WrongArchitecture => Self::WrongArchitecture,
            Sha512BackendError::NotAdmitted => Self::BackendNotAdmitted,
            Sha512BackendError::Quarantined => Self::BackendQuarantined,
            _ => Self::BackendUnavailable,
        }
    }
}

pub(crate) fn checked_message_length(
    current: u128,
    additional: u128,
) -> Result<u128, MessageTooLong> {
    current
        .checked_add(additional)
        .filter(|length| *length <= MAX_MESSAGE_BYTES)
        .ok_or(MessageTooLong)
}

pub(crate) const fn padding_block_count(buffer_len: usize) -> usize {
    if buffer_len < FINAL_BLOCK_PREFIX_BYTES {
        1
    } else {
        2
    }
}

#[cfg(test)]
mod tests {
    use super::{MAX_MESSAGE_BYTES, Sha512State};

    #[cfg(feature = "cpu")]
    use brynja_crypto_cpu::Sha512BackendSession;

    #[test]
    fn rejected_update_preserves_every_shared_owned_field() {
        let mut state = Sha512State::new([0x55aa; 8]);
        assert_eq!(state.update(b"retained prefix"), Ok(()));
        state.message_bytes = MAX_MESSAGE_BYTES;
        let expected_state = state.state;
        let expected_buffer = state.buffer;
        let expected_buffer_len = state.buffer_len;
        let expected_message_bytes = state.message_bytes;

        assert!(state.update(b"x").is_err());
        assert_eq!(state.state, expected_state);
        assert_eq!(state.buffer, expected_buffer);
        assert_eq!(state.buffer_len, expected_buffer_len);
        assert_eq!(state.message_bytes, expected_message_bytes);
    }

    #[cfg(feature = "cpu")]
    #[test]
    fn accelerated_rejected_update_preserves_every_shared_owned_field() {
        let Some(backend) = Sha512BackendSession::for_compiled_target() else {
            return;
        };
        let mut state = Sha512State::new([0x55aa; 8]);
        assert_eq!(state.update(b"retained prefix"), Ok(()));
        state.message_bytes = MAX_MESSAGE_BYTES;
        let expected = (
            state.state,
            state.buffer,
            state.buffer_len,
            state.message_bytes,
        );

        assert_eq!(
            state.update_with_backend(b"x", &backend),
            Err(super::Sha512AcceleratedError::MessageTooLong)
        );
        assert_eq!(
            (
                state.state,
                state.buffer,
                state.buffer_len,
                state.message_bytes
            ),
            expected
        );
    }
}
