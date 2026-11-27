//! Raw RFC 8439 ChaCha20 for building reviewed compositions. XOR encryption alone
//! does not authenticate: a changed ciphertext produces changed plaintext without
//! an error. This is not ChaCha20-Poly1305. Never reuse a key/nonce stream for
//! different messages; allocating unique nonces across owners is the caller's job.

mod block;
#[cfg(any(
    all(
        feature = "chacha20-sse2",
        target_arch = "x86_64",
        target_feature = "sse2"
    ),
    all(
        feature = "chacha20-neon",
        target_arch = "aarch64",
        target_feature = "neon",
        target_endian = "little"
    )
))]
pub(crate) mod execution;
use core::{num::NonZeroUsize, ops::RangeInclusive};

// 2^32 blocks of 64 bytes, with a representable one-past-the-end position.
const END: u64 = 1 << 38;

// Only constructed after reserving the exact length of this buffer.
struct Admitted<'a> {
    data: &'a mut [u8],
    counters: RangeInclusive<u32>,
    skip: usize,
}

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
/// Clearing named working arrays does not erase compiler spills or registers.
/// Do not rely on this API to keep a raw key out of a stack dump.
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
        self.apply(data, None, Admitted::xor)
    }

    /// XOR from a separate, nonoverlapping input. Safe Rust prevents partial
    /// overlap; use the in-place method for exactly coincident buffers.
    pub fn apply_keystream(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        self.apply(output, Some(input), Admitted::xor)
    }

    fn apply<'a>(
        &mut self,
        output: &'a mut [u8],
        input: Option<&[u8]>,
        xor: impl FnOnce(Admitted<'a>, &[u8; 32], &[u8; 12]),
    ) -> Result<(), Error> {
        if input.is_some_and(|source| source.len() != output.len()) {
            return Err(Error::LengthMismatch);
        }
        if let Some(admitted) = self.admit(output)? {
            if let Some(source) = input {
                admitted.data.copy_from_slice(source);
            }
            xor(admitted, self.key, &self.nonce);
        }
        Ok(())
    }

    fn admit<'a>(&mut self, data: &'a mut [u8]) -> Result<Option<Admitted<'a>>, Error> {
        let Some(len) = NonZeroUsize::new(data.len()) else {
            return Ok(None);
        };
        let (counters, skip) = self.reserve(len)?;
        Ok(Some(Admitted {
            data,
            counters,
            skip,
        }))
    }

    fn reserve(&mut self, len: NonZeroUsize) -> Result<(RangeInclusive<u32>, usize), Error> {
        let start = self.position;
        let end = start
            .checked_add(u64::try_from(len.get()).map_err(|_| Error::Exhausted)?)
            .filter(|end| *end <= END)
            .ok_or(Error::Exhausted)?;
        let first = u32::try_from(start >> 6).map_err(|_| Error::Exhausted)?;
        let last_byte = end.checked_sub(1).ok_or(Error::Exhausted)?;
        let last = u32::try_from(last_byte >> 6).map_err(|_| Error::Exhausted)?;
        self.position = end;
        Ok((first..=last, usize::from(start.to_le_bytes()[0] & 63)))
    }
}

#[cfg(kani)]
#[kani::proof]
fn admitted_requests_cannot_wrap_the_counter() {
    let start: u64 = kani::any();
    kani::assume(start <= END);
    let Some(size) = NonZeroUsize::new(kani::any()) else {
        return;
    };
    let mut owner = ChaCha20 {
        key: &[0; 32],
        nonce: [0; 12],
        position: start,
    };
    let bytes = size.get() as u128;
    let exact = u128::from(start) + bytes;
    match owner.reserve(size) {
        Ok((counters, skip)) => {
            assert!(exact <= u128::from(END));
            assert_eq!(u128::from(owner.position), exact);
            assert_eq!(skip as u64, start % 64);
            let first = u128::from(*counters.start());
            let last = u128::from(*counters.end());
            assert_eq!(first, u128::from(start / 64));
            assert_eq!(last, (exact - 1) / 64);
            assert_eq!(last - first + 1, (skip as u128 + bytes).div_ceil(64));
        }
        Err(Error::Exhausted) => {
            assert!(exact > u128::from(END));
            assert_eq!(owner.position, start);
        }
        Err(Error::LengthMismatch) => unreachable!(),
    }
}
