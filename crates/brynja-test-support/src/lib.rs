//! Repository-only test support for Brynja.
//!
//! This unpublished package owns diagnostic helpers that must never enter a
//! production package, feature, resolved graph, or release archive.

#![no_std]

pub mod keylog;

pub use keylog::{KeyLogError, KeyLogLabel, LineEnding, write_line};

/// Whether this package provides its planned implementation.
///
/// The foundation release intentionally reports `false`.
pub const IMPLEMENTED: bool = false;

/// Whether isolated RFC 9850 test-support encoding is implemented.
pub const KEYLOG_TEST_SUPPORT_IMPLEMENTED: bool = true;

#[cfg(test)]
mod tests {
    #[test]
    fn foundation_does_not_claim_implementation() {
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
        assert!(::core::hint::black_box(
            super::KEYLOG_TEST_SUPPORT_IMPLEMENTED
        ));
    }
}
