//! Explicit facade for isolated historical protocol packages.
//!
//! No feature is enabled by default. Historical engines must never share a
//! negotiation path, session cache, or ticket keys with modern Brynja.

#![no_std]

/// Whether this package provides its planned implementation.
///
/// The foundation release intentionally reports `false`.
pub const IMPLEMENTED: bool = false;

#[cfg(feature = "pct")]
pub use brynja_pct as pct;
#[cfg(feature = "snp")]
pub use brynja_snp as snp;
#[cfg(feature = "ssl2")]
pub use brynja_ssl2 as ssl2;
#[cfg(feature = "ssl3")]
pub use brynja_ssl3 as ssl3;
#[cfg(feature = "tls10")]
pub use brynja_tls10 as tls10;
#[cfg(feature = "tls11")]
pub use brynja_tls11 as tls11;
#[cfg(feature = "wtls")]
pub use brynja_wtls as wtls;

#[cfg(test)]
mod tests {
    #[test]
    fn foundation_does_not_claim_implementation() {
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
    }
}
