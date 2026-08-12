//! Repository-only test support for Brynja.
//!
//! This unpublished package owns diagnostic helpers that must never enter a
//! production package, feature, resolved graph, or release archive.

#![no_std]

pub mod deterministic_clock;
pub mod deterministic_random;
pub mod keylog;

pub use deterministic_clock::{
    DeterministicMonotonicClock, DeterministicReading, DeterministicWallClock,
};

pub use deterministic_random::{DeterministicFault, DeterministicRandom};
pub use keylog::{KeyLogError, KeyLogLabel, LineEnding, write_line};

/// Whether this package provides its planned implementation.
///
/// The foundation release intentionally reports `false`.
pub const IMPLEMENTED: bool = false;

/// Whether isolated RFC 9850 test-support encoding is implemented.
pub const KEYLOG_TEST_SUPPORT_IMPLEMENTED: bool = true;

/// Whether isolated deterministic secure-random test support is implemented.
pub const DETERMINISTIC_RANDOM_TEST_SUPPORT_IMPLEMENTED: bool = true;

/// Whether isolated deterministic clock test support is implemented.
pub const DETERMINISTIC_CLOCK_TEST_SUPPORT_IMPLEMENTED: bool = true;

#[cfg(test)]
mod tests {
    #[test]
    fn foundation_does_not_claim_implementation() {
        assert!(!::core::hint::black_box(super::IMPLEMENTED));
        assert!(::core::hint::black_box(
            super::KEYLOG_TEST_SUPPORT_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::DETERMINISTIC_RANDOM_TEST_SUPPORT_IMPLEMENTED
        ));
        assert!(::core::hint::black_box(
            super::DETERMINISTIC_CLOCK_TEST_SUPPORT_IMPLEMENTED
        ));
    }
}
