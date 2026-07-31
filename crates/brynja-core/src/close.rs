//! Non-error closure and cancellation outcomes.

use crate::{Alert, AlertClass, AlertOrigin, ProtocolVersion};

/// An orderly `close_notify` outcome.
///
/// The type has no formatting implementation and carries no peer-controlled
/// text or secret bytes.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct CloseOutcome {
    version: ProtocolVersion,
    origin: AlertOrigin,
}

/// An explicit `user_canceled` outcome.
///
/// Cancellation remains separate from both orderly close and failure.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct Cancellation {
    version: ProtocolVersion,
    origin: AlertOrigin,
}

impl CloseOutcome {
    /// Converts only an orderly-close alert.
    #[must_use]
    pub const fn from_alert(alert: Alert) -> Option<Self> {
        if matches!(alert.class(), AlertClass::Closure) {
            Some(Self {
                version: alert.version(),
                origin: alert.origin(),
            })
        } else {
            None
        }
    }

    /// Returns the concrete protocol version.
    #[must_use]
    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    /// Returns which party initiated orderly closure.
    #[must_use]
    pub const fn origin(self) -> AlertOrigin {
        self.origin
    }
}

impl Cancellation {
    /// Converts only an explicit cancellation alert.
    #[must_use]
    pub const fn from_alert(alert: Alert) -> Option<Self> {
        if matches!(alert.class(), AlertClass::Cancellation) {
            Some(Self {
                version: alert.version(),
                origin: alert.origin(),
            })
        } else {
            None
        }
    }

    /// Returns the concrete protocol version.
    #[must_use]
    pub const fn version(self) -> ProtocolVersion {
        self.version
    }

    /// Returns which party canceled the handshake.
    #[must_use]
    pub const fn origin(self) -> AlertOrigin {
        self.origin
    }
}
