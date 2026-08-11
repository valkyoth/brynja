//! Reserved host CPU-detection boundary for Brynja cryptography.
//!
//! This placeholder deliberately remains `no_std`: v0.13.2 reserves the
//! future opt-in host adapter but authorizes no runtime detection or dispatch
//! implementation. A later implementation milestone must explicitly amend
//! the boundary before standard-library use is admitted.

#![no_std]

/// The Brynja milestone that froze this package boundary.
pub const BOUNDARY_MILESTONE: &str = "0.13.2";

/// Whether host runtime CPU detection is implemented.
pub const RUNTIME_DETECTION_IMPLEMENTED: bool = false;

/// Whether the required no_std CPU package currently contains a backend.
pub const CPU_BACKEND_IMPLEMENTED: bool = brynja_crypto_cpu::IMPLEMENTED;

#[cfg(test)]
mod tests {
    #[test]
    fn reserved_adapter_detects_and_activates_nothing() {
        assert!(!::core::hint::black_box(
            super::RUNTIME_DETECTION_IMPLEMENTED
        ));
        assert!(!::core::hint::black_box(super::CPU_BACKEND_IMPLEMENTED));
        assert_eq!(super::BOUNDARY_MILESTONE, "0.13.2");
    }
}
