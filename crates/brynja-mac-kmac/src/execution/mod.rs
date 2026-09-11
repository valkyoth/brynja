//! Default-off KMAC operations over portable or authorized hardened cSHAKE.
//!
//! Selection happens before key absorption. A missing preferred capability may
//! select portable execution; an unhealthy supplied capability never falls back.
//! Fixed finalization consumes the MAC. XOF readers exclusively borrow the exact
//! in-place source owner, and clear it when dropped. Forgetting a reader cannot
//! reopen absorption. Owners are sealed, non-cloneable and thread-bound.
//! Caller inputs, compiler copies/registers/spills and platform storage remain
//! outside the source-owned memory clearing guarantee. No FIPS claim is made.

mod backend;
mod core_state;
mod fixed;
mod output;
mod xof;

pub use crate::KmacError as Error;
pub use brynja_hash_sha3::hardened_execution::{KeccakSession, Report};
pub use fixed::{Kmac128, Kmac256};
pub use xof::{KmacXof128, KmacXof256, Reader};

/// Explicit selection; carries authority, not a boolean CPU-feature assertion.
pub enum Mode<'a> {
    /// Use only the portable hardened implementation.
    Portable,
    /// Use the supplied capability, or portable only if no capability exists.
    Prefer(Option<KeccakSession<'a>>),
    /// Reject absence and all capability/backend failures.
    Require(Option<KeccakSession<'a>>),
}

mod sealed {
    pub trait State {}
}
/// A first-party erasing owner, not independent review or deployment approval.
pub trait HardenedState: sealed::State {}

macro_rules! seal {
    ($($name:ident),+) => {$(
        impl sealed::State for $name<'_> {}
        impl HardenedState for $name<'_> {}
    )+};
}
seal!(Kmac128, Kmac256, KmacXof128, KmacXof256);
impl sealed::State for Reader<'_, '_> {}
impl HardenedState for Reader<'_, '_> {}

fn bits(input: &[u8]) -> Result<crate::Fips202BitString<'_>, Error> {
    crate::Fips202BitString::new(input, if input.is_empty() { 0 } else { 8 })
        .map_err(|_| Error::InvalidBitString)
}
