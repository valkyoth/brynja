//! Default-off TupleHash operations over portable or authorized hardened cSHAKE.
//!
//! Ordinary-public and secret-bearing owners have separate output APIs. All
//! internal variants erase owned state; ordinary types are not secret capabilities.
//! Item writers and XOF readers borrow the exact original owner. An abandoned
//! item, failed operation, cancellation or recoverable unwind closes and clears it.
//! Fixed finalizers consume their owner. No supplied-backend failure falls back.
//! Registers, compiler copies/spills, forgotten owners and platform storage are
//! not covered. These APIs do not claim independent verification or FIPS validation.

mod backend;
mod common;
mod core_state;
mod fixed;
mod item;
mod output;
mod ownership;
mod xof;

pub use crate::TupleHashError as Error;
pub use brynja_hash_sha3::hardened_execution::{KeccakSession, Report};
pub use fixed::{HardenedTupleHash128, HardenedTupleHash256, TupleHash128, TupleHash256};
pub use item::TupleItemWriter;
pub use xof::{
    HardenedReader, HardenedTupleHashXof128, HardenedTupleHashXof256, Reader, TupleHashXof128,
    TupleHashXof256,
};

/// Selects a route before absorbing any customization or item data.
pub enum Mode<'a> {
    /// Always use the portable hardened implementation.
    Portable,
    /// Use supplied authority, or portable only when authority is absent.
    Prefer(Option<KeccakSession<'a>>),
    /// Require supplied authority; absence and backend failure are errors.
    Require(Option<KeccakSession<'a>>),
}
mod sealed {
    pub trait State {}
}
/// Sealed secret-bearing ownership, not deployment approval or verification.
pub trait HardenedState: sealed::State {}
macro_rules! seal { ($($name:ident),+) => {$(
    impl sealed::State for $name<'_> {}
    impl HardenedState for $name<'_> {}
)+}; }
seal!(
    HardenedTupleHash128,
    HardenedTupleHash256,
    HardenedTupleHashXof128,
    HardenedTupleHashXof256
);
impl sealed::State for HardenedReader<'_, '_> {}
impl HardenedState for HardenedReader<'_, '_> {}

fn bits(input: &[u8]) -> Result<crate::Fips202BitString<'_>, Error> {
    crate::Fips202BitString::new(input, output::valid(input.len()))
        .map_err(|_| Error::InvalidBitString)
}
