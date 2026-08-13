//! Explicit caller-owned timestamp enrichment.

use crate::{MonotonicInstant, WallTime};

use super::SecurityEvent;

/// Optional caller-provided time attached to one observational event.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityEventTimestamp {
    /// No clock was available or consulted.
    Untimestamped,
    /// Caller-provided adjustable wall time.
    Wall(WallTime),
    /// Caller-provided generation-bound monotonic time.
    Monotonic(MonotonicInstant),
}

/// Failure to enrich one event record.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityEventTimestampError {
    /// The record already has a timestamp and cannot be relabeled.
    AlreadyTimestamped,
    /// Enrichment must supply an actual clock observation.
    UntimestampedInput,
}

/// One event and its explicit caller-owned timestamp state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecurityEventRecord {
    event: SecurityEvent,
    timestamp: SecurityEventTimestamp,
}

impl SecurityEventRecord {
    /// Creates an explicitly untimestamped event for timestamp-free boot.
    #[must_use]
    pub const fn untimestamped(event: SecurityEvent) -> Self {
        Self {
            event,
            timestamp: SecurityEventTimestamp::Untimestamped,
        }
    }

    /// Adds one later caller timestamp without replacing an earlier value.
    pub fn enrich(
        &mut self,
        timestamp: SecurityEventTimestamp,
    ) -> Result<(), SecurityEventTimestampError> {
        if !matches!(self.timestamp, SecurityEventTimestamp::Untimestamped) {
            return Err(SecurityEventTimestampError::AlreadyTimestamped);
        }
        if matches!(timestamp, SecurityEventTimestamp::Untimestamped) {
            return Err(SecurityEventTimestampError::UntimestampedInput);
        }
        self.timestamp = timestamp;
        Ok(())
    }

    /// Returns the duplicated security event.
    #[must_use]
    pub const fn event(self) -> SecurityEvent {
        self.event
    }

    /// Returns the explicit timestamp state.
    #[must_use]
    pub const fn timestamp(self) -> SecurityEventTimestamp {
        self.timestamp
    }
}
