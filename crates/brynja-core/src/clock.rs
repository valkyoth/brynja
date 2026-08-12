//! Typed wall-clock and monotonic-clock foundations.
//!
//! Wall time is an externally adjustable civil-time input suitable for later
//! PKI policy. Monotonic time is generation-bound process/runtime input for
//! timers, freshness, tickets, and replay policy. The domains are deliberately
//! non-interchangeable and this module performs no operating-system access.
//!
//! ```compile_fail
//! fn confuse(time: brynja_core::WallTime) -> brynja_core::MonotonicInstant {
//!     time
//! }
//! ```
//!
//! ```compile_fail
//! fn forge() -> brynja_core::MonotonicInstant {
//!     brynja_core::MonotonicInstant {
//!         generation: brynja_core::ClockGeneration::new(1).unwrap(),
//!         tick_nanoseconds: 0,
//!     }
//! }
//! ```

mod duration;
mod monotonic;
mod wall;

pub use duration::{ClockDuration, NANOS_PER_SECOND, TimeError};
pub use monotonic::{
    ClockGeneration, ClockUnavailable, DeadlineStatus, MonotonicClock, MonotonicClockError,
    MonotonicClockSource, MonotonicDeadline, MonotonicInstant, MonotonicPurpose,
};
pub use wall::{WallClockSource, WallTime, WallTimeRange, WallTimeStatus};
