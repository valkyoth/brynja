//! Complete portable SP 800-185 TupleHash and TupleHashXOF functions.
//!
//! Tuple items are structural API operations: callers cannot accidentally
//! substitute one flattened byte string for a tuple. Both security strengths
//! support byte and canonical arbitrary-bit items, fixed and incremental XOF
//! output, exact-length streamed items, and distinct hardened state owners.

#![no_std]

mod backend;
mod core_state;
mod error;
mod fixed;
mod item;
mod output;
mod secret_encoding;
mod xof;

pub use brynja_hash_sha3::{Fips202BitString, Fips202BitsError, Fips202Output};
pub use error::TupleHashError;
pub use fixed::{HardenedTupleHash128, HardenedTupleHash256, TupleHash128, TupleHash256};
pub use item::TupleItemWriter;
pub use output::{TupleHashPublicDeclassification, TupleHashSecretOutput};
pub use xof::{
    HardenedTupleHashXof128, HardenedTupleHashXof128Reader, HardenedTupleHashXof256,
    HardenedTupleHashXof256Reader, TupleHashXof128, TupleHashXof128Reader, TupleHashXof256,
    TupleHashXof256Reader,
};

/// Whether all four SP 800-185 TupleHash identities are implemented.
pub const TUPLE_HASH_IMPLEMENTED: bool = true;

/// Hashes one byte-oriented tuple with TupleHash128.
pub fn tuple_hash128(
    items: &[&[u8]],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), TupleHashError> {
    let mut state = TupleHash128::new(customization)?;
    for item in items {
        state.push_item(item)?;
    }
    state.finalize(output)
}

/// Hashes one byte-oriented tuple with TupleHash256.
pub fn tuple_hash256(
    items: &[&[u8]],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), TupleHashError> {
    let mut state = TupleHash256::new(customization)?;
    for item in items {
        state.push_item(item)?;
    }
    state.finalize(output)
}

/// Hashes one arbitrary-bit tuple with TupleHash128.
pub fn tuple_hash128_bits(
    items: &[Fips202BitString<'_>],
    customization: Fips202BitString<'_>,
    output: Fips202Output<'_>,
) -> Result<(), TupleHashError> {
    let mut state = TupleHash128::new_bits(customization)?;
    for item in items {
        state.push_item_bits(*item)?;
    }
    state.finalize_bits(output)
}

/// Hashes one arbitrary-bit tuple with TupleHash256.
pub fn tuple_hash256_bits(
    items: &[Fips202BitString<'_>],
    customization: Fips202BitString<'_>,
    output: Fips202Output<'_>,
) -> Result<(), TupleHashError> {
    let mut state = TupleHash256::new_bits(customization)?;
    for item in items {
        state.push_item_bits(*item)?;
    }
    state.finalize_bits(output)
}

/// Produces one byte-oriented TupleHashXOF128 output.
pub fn tuple_hash_xof128(
    items: &[&[u8]],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), TupleHashError> {
    let mut state = TupleHashXof128::new(customization)?;
    for item in items {
        state.push_item(item)?;
    }
    state.finalize_xof()?.squeeze(output)
}

/// Produces one byte-oriented TupleHashXOF256 output.
pub fn tuple_hash_xof256(
    items: &[&[u8]],
    customization: &[u8],
    output: &mut [u8],
) -> Result<(), TupleHashError> {
    let mut state = TupleHashXof256::new(customization)?;
    for item in items {
        state.push_item(item)?;
    }
    state.finalize_xof()?.squeeze(output)
}

/// Produces one arbitrary-bit TupleHashXOF128 output.
pub fn tuple_hash_xof128_bits(
    items: &[Fips202BitString<'_>],
    customization: Fips202BitString<'_>,
    output: Fips202Output<'_>,
) -> Result<(), TupleHashError> {
    let mut state = TupleHashXof128::new_bits(customization)?;
    for item in items {
        state.push_item_bits(*item)?;
    }
    state.finalize_xof()?.squeeze_final_bits(output)
}

/// Produces one arbitrary-bit TupleHashXOF256 output.
pub fn tuple_hash_xof256_bits(
    items: &[Fips202BitString<'_>],
    customization: Fips202BitString<'_>,
    output: Fips202Output<'_>,
) -> Result<(), TupleHashError> {
    let mut state = TupleHashXof256::new_bits(customization)?;
    for item in items {
        state.push_item_bits(*item)?;
    }
    state.finalize_xof()?.squeeze_final_bits(output)
}

#[cfg(kani)]
mod proofs {
    use super::{TupleHashError, core_state::checked_remaining_after};

    #[kani::proof]
    fn production_item_reservation_is_exact() {
        let remaining: u128 = kani::any();
        let fragment: u128 = kani::any();
        let result = checked_remaining_after(remaining, fragment);
        assert_eq!(result.is_ok(), fragment <= remaining);
        if let Ok(next) = result {
            assert_eq!(next, remaining - fragment);
        }
    }

    #[kani::proof]
    fn output_byte_to_bit_bound_is_checked() {
        let length: usize = kani::any();
        let result = super::core_state::output_bits(length);
        let expected = u128::try_from(length)
            .ok()
            .and_then(|value| value.checked_mul(8));
        assert_eq!(result, expected.ok_or(TupleHashError::OutputTooLong));
    }
}
