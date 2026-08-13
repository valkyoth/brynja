//! Bounded observational security events.
//!
//! Events duplicate authoritative [`crate::security_outcome`] state for audit
//! consumers. They never authorize, commit, complete, alert, or execute work.

mod event;
mod queue;
mod record;

pub use event::{SecurityEvent, SecurityEventKind};
pub use queue::{
    SecurityEventDropCount, SecurityEventPush, SecurityEventQueue, SecurityEventQueueSnapshot,
};
pub use record::{SecurityEventRecord, SecurityEventTimestamp, SecurityEventTimestampError};
