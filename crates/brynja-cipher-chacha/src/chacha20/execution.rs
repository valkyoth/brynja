//! Shared framing for statically selected four-lane stream kernels.
use super::{Admitted, ChaCha20, Error};
mod layout;
#[cfg(target_arch = "aarch64")]
use brynja_crypto_cpu::chacha20_neon::four_lane_rounds_without_feedforward as rounds;
#[cfg(target_arch = "x86_64")]
use brynja_crypto_cpu::chacha20_sse2::four_lane_rounds_without_feedforward as rounds;

/// Raw IETF ChaCha20 with four-block SIMD batches. This owner is available only
/// with the corresponding feature on an x86-64 SSE2 or little-endian AArch64 NEON target; no runtime probing or
/// thread scheduling is performed. A leading partial block and trailing fewer
/// than four blocks use the portable rounds. Stream limits, key ownership and
/// nonce obligations are identical to [`ChaCha20`]. This is not an AEAD.
pub struct ParallelChaCha20<'key>(ChaCha20<'key>);

impl<'key> ParallelChaCha20<'key> {
    /// Start at an explicit IETF block counter.
    #[must_use]
    pub fn new(key: &'key [u8; 32], nonce: [u8; 12], initial_counter: u32) -> Self {
        Self(ChaCha20::new(key, nonce, initial_counter))
    }
    /// Number of bytes left before counter exhaustion.
    #[must_use]
    pub fn remaining_bytes(&self) -> u64 {
        self.0.remaining_bytes()
    }

    /// XOR a request in place after checking its entire counter range.
    pub fn apply_keystream_in_place(&mut self, data: &mut [u8]) -> Result<(), Error> {
        self.0.apply(data, None, Admitted::xor_four)
    }
    /// XOR disjoint buffers; a length mismatch or exhaustion changes neither
    /// the destination nor the stream position.
    pub fn apply_keystream(&mut self, input: &[u8], output: &mut [u8]) -> Result<(), Error> {
        self.0.apply(output, Some(input), Admitted::xor_four)
    }
}

impl Admitted<'_> {
    fn xor_four(self, key: &[u8; 32], nonce: &[u8; 12]) {
        let Self {
            data,
            counters,
            skip,
        } = self;
        let first = *counters.start();
        let plan = layout::Layout::new(first, *counters.end(), skip, data.len());
        let (head, rest) = data.split_at_mut(plan.head);
        if !head.is_empty() {
            Admitted {
                data: head,
                counters: first..=first,
                skip,
            }
            .xor(key, nonce);
        }
        let (groups, tail) = rest.as_chunks_mut::<256>();
        for (group, lanes) in groups.iter_mut().zip(plan.groups()) {
            xor4(key, nonce, lanes, group);
        }
        if let Some(counters) = plan.tail {
            Admitted {
                data: tail,
                counters,
                skip: 0,
            }
            .xor(key, nonce);
        }
    }
}

type Word = [u8; 4];
type Column = [Word; 4];
struct State([Column; 16]);

impl Drop for State {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(self.0.as_flattened_mut().as_flattened_mut());
    }
}

// Called only for a complete four-block group in an already admitted range.
#[inline(never)]
fn xor4(key: &[u8; 32], nonce: &[u8; 12], lanes: [u32; 4], data: &mut [u8; 256]) {
    let mut initial = State([[[0; 4]; 4]; 16]);
    let constants = b"expand 32-byte k".as_chunks::<4>().0;
    for (column, word) in initial.0[..12]
        .iter_mut()
        .zip(constants.iter().chain(key.as_chunks::<4>().0))
    {
        *column = [*word; 4];
    }
    initial.0[12] = lanes.map(u32::to_le_bytes);
    for (column, word) in initial.0[13..].iter_mut().zip(nonce.as_chunks::<4>().0) {
        *column = [*word; 4];
    }
    let mut work = State(initial.0);
    rounds(&mut work.0);
    // Word i occupies the same offset in each of the four consecutive blocks.
    let outputs = data.as_chunks_mut::<4>().0;
    for (i, (sums, bases)) in work.0.iter().zip(&initial.0).enumerate() {
        for ((out, sum), base) in outputs.iter_mut().skip(i).step_by(16).zip(sums).zip(bases) {
            let word = u32::from_le_bytes(*sum).wrapping_add(u32::from_le_bytes(*base));
            *out = (u32::from_le_bytes(*out) ^ word).to_le_bytes();
        }
    }
}
