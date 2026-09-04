//! Complete portable SP 800-185 ParallelHash and ParallelHashXOF functions.
//!
//! The sequential API is allocation-free and takes a caller-owned workspace
//! whose positive length is the standard parameter `B`. The scheduling API
//! exposes exact indexed leaf jobs and accepts results only in standard order.
//! Both paths reuse Brynja's hardened cSHAKE owner and clear every crate-owned
//! or temporarily borrowed secret-bearing region.

#![no_std]

mod backend;
mod core_state;
mod error;
mod fixed;
mod output;
mod scheduled;
mod xof;

pub use brynja_hash_sha3::{Fips202BitString, Fips202BitsError, Fips202Output};
pub use error::ParallelHashError;
pub use fixed::{
    HardenedParallelHash128, HardenedParallelHash256, ParallelHash128, ParallelHash256,
};
pub use output::{ParallelHashPublicDeclassification, ParallelHashSecretOutput};
pub use scheduled::{
    ParallelHash128Collector, ParallelHash128LeafJob, ParallelHash128LeafResult,
    ParallelHash128Plan, ParallelHash128ScheduledXofReader, ParallelHash256Collector,
    ParallelHash256LeafJob, ParallelHash256LeafResult, ParallelHash256Plan,
    ParallelHash256ScheduledXofReader,
};
pub use xof::{
    HardenedParallelHashXof128, HardenedParallelHashXof128Reader, HardenedParallelHashXof256,
    HardenedParallelHashXof256Reader, ParallelHashXof128, ParallelHashXof128Reader,
    ParallelHashXof256, ParallelHashXof256Reader,
};

/// Whether all four SP 800-185 ParallelHash identities are implemented.
pub const PARALLEL_HASH_IMPLEMENTED: bool = true;

/// Computes byte-oriented ParallelHash128 using caller workspace as `B`.
pub fn parallel_hash128(
    input: &[u8],
    workspace: &mut [u8],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), ParallelHashError> {
    let mut state = ParallelHash128::new(workspace, customization)?;
    state.update(input)?;
    state.finalize(output)
}

/// Computes byte-oriented ParallelHash256 using caller workspace as `B`.
pub fn parallel_hash256(
    input: &[u8],
    workspace: &mut [u8],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), ParallelHashError> {
    let mut state = ParallelHash256::new(workspace, customization)?;
    state.update(input)?;
    state.finalize(output)
}

/// Computes byte-oriented ParallelHashXOF128 using caller workspace as `B`.
pub fn parallel_hash_xof128(
    input: &[u8],
    workspace: &mut [u8],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), ParallelHashError> {
    let mut state = ParallelHashXof128::new(workspace, customization)?;
    state.update(input)?;
    state.finalize_xof()?.squeeze(output)
}

/// Computes byte-oriented ParallelHashXOF256 using caller workspace as `B`.
pub fn parallel_hash_xof256(
    input: &[u8],
    workspace: &mut [u8],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), ParallelHashError> {
    let mut state = ParallelHashXof256::new(workspace, customization)?;
    state.update(input)?;
    state.finalize_xof()?.squeeze(output)
}

#[cfg(kani)]
mod proofs {
    use super::scheduled::leaf_count;

    #[kani::proof]
    fn leaf_count_is_exact_for_small_domains() {
        let bits: usize = kani::any();
        let block: usize = kani::any();
        kani::assume(bits <= 4_096);
        kani::assume(block <= 128);
        if block != 0 {
            let block_bits = block * 8;
            let expected = (bits + block_bits - 1) / block_bits;
            assert_eq!(
                leaf_count(bits, block),
                u128::try_from(expected).map_err(|_| super::ParallelHashError::MessageTooLong)
            );
        }
    }
}
