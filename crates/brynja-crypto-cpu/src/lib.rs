//! Reserved first-party CPU-acceleration boundary for Brynja cryptography.
//!
//! Version 0.1.0 contains no ISA kernel, detection, dispatch, or executable
//! cryptographic operation. Future implementation symbols require separate
//! primitive-specific admission.

#![no_std]

/// The Brynja milestone that froze this package boundary.
pub const BOUNDARY_MILESTONE: &str = "0.13.2";

/// Whether any accelerated implementation is present.
pub const IMPLEMENTED: bool = false;

/// Number of accelerated backend symbols admitted for execution.
pub const ADMITTED_BACKEND_COUNT: usize = 0;

#[cfg(test)]
mod tests {
    #[test]
    fn reserved_boundary_authorizes_no_backend() {
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
        assert_eq!(::core::hint::black_box(super::ADMITTED_BACKEND_COUNT), 0);
        assert_eq!(super::BOUNDARY_MILESTONE, "0.13.2");
    }
}
