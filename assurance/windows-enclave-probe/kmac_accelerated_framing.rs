//! Compile the existing first-party suffix packer unchanged. Only its Absorb
//! port is used by this component. The unused portable adapter trait below is
//! a compile-time shim, not a fallback implementation.
#[allow(dead_code)]
pub(super) mod backend {
    use brynja_mac_kmac::{Fips202BitString, KmacError};
    pub trait CshakeState {
        type Reader;
        fn update(&mut self, input: &[u8]) -> Result<(), KmacError>;
        fn finalize_bits_xof_erasing_source(
            &mut self,
            input: Fips202BitString<'_>,
        ) -> Result<Self::Reader, KmacError>;
        fn finalize_xof_erasing_source(&mut self) -> Result<Self::Reader, KmacError>;
    }
}
pub(super) mod error {
    pub use brynja_mac_kmac::KmacError;
}
#[allow(dead_code)]
#[path = "kmac_packer.rs"]
pub(super) mod packer;
