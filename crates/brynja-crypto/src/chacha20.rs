//! Raw RFC 8439 ChaCha20 for building reviewed compositions. XOR encryption alone
//! does not authenticate: a changed ciphertext produces changed plaintext without
//! an error. This is not ChaCha20-Poly1305. Never reuse a key/nonce stream for
//! different messages; allocating unique nonces across owners is the caller's job.

#![forbid(unsafe_code)]

mod block;

// 2^32 blocks of 64 bytes, with a representable one-past-the-end position.
const END: u64 = 1 << 38;

/// Failure before changing the destination or consuming stream bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// A disjoint source and destination must have identical lengths.
    LengthMismatch,
    /// The whole request would cross the last byte of counter 0xffff_ffff.
    Exhausted,
}

/// A forward-only IETF stream (256-bit key, 96-bit nonce, 32-bit counter).
/// There is no reset, seek, or clone. A fragmented call continues at the next
/// byte, even in the middle of a block. No keystream is retained between calls.
/// The key is borrowed, not cleared on drop; callers own its storage.
pub struct ChaCha20<'key> {
    key: &'key [u8; 32],
    nonce: [u8; 12],
    position: u64,
}

impl<'key> ChaCha20<'key> {
    /// Start at an explicit block counter. A protocol must reserve any blocks
    /// it uses for other purposes (e.g. block zero in RFC 8439 AEAD).
    #[must_use]
    pub fn new(key: &'key [u8; 32], nonce: [u8; 12], initial_counter: u32) -> Self {
        Self {
            key,
            nonce,
            position: u64::from(initial_counter) << 6,
        }
    }

    /// Number of bytes still available, including an unconsumed final tail.
    #[must_use]
    pub fn remaining_bytes(&self) -> u64 {
        END.saturating_sub(self.position)
    }

    /// XOR data in place. An empty request succeeds even after exhaustion.
    pub fn apply_keystream_in_place(&mut self, data: &mut [u8]) -> Result<(), Error> {
        if !data.is_empty() {
            let (counter, skip) = self.reserve(data.len())?;
            block::xor(self.key, &self.nonce, counter, skip, data);
        }
        Ok(())
    }

    /// XOR from a separate, nonoverlapping input. Safe Rust prevents partial
    /// overlap; use the in-place method for exactly coincident buffers.
    pub fn apply_keystream(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        if input.len() != output.len() {
            return Err(Error::LengthMismatch);
        }
        if !input.is_empty() {
            let (counter, skip) = self.reserve(input.len())?;
            output.copy_from_slice(input);
            block::xor(self.key, &self.nonce, counter, skip, output);
        }
        Ok(())
    }

    fn reserve(&mut self, len: usize) -> Result<(u32, usize), Error> {
        let start = self.position;
        let end = end_position(start, u64::try_from(len).map_err(|_| Error::Exhausted)?)
            .ok_or(Error::Exhausted)?;
        let counter = u32::try_from(start >> 6).map_err(|_| Error::Exhausted)?;
        self.position = end;
        Ok((counter, usize::from(start.to_le_bytes()[0] & 63)))
    }
}

fn end_position(start: u64, bytes: u64) -> Option<u64> {
    start.checked_add(bytes).filter(|end| *end <= END)
}

#[cfg(kani)]
#[kani::proof]
fn admitted_requests_cannot_wrap_the_counter() {
    let start: u64 = kani::any();
    let size: u64 = kani::any();
    let exact = u128::from(start) + u128::from(size);
    match end_position(start, size) {
        Some(end) => {
            assert_eq!(u128::from(end), exact);
            assert!(end <= END);
            if size != 0 {
                assert!(u32::try_from(start / 64).is_ok());
                assert!(u32::try_from((end - 1) / 64).is_ok());
            }
        }
        None => assert!(exact > u128::from(END)),
    }
}
