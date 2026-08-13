//! Secret-free event discriminants derived from authoritative values.

use crate::{
    SecurityAccepted, SecurityApproved, SecurityAuthoritySnapshot, SecurityAuthorityState,
    SecurityCanceled, SecurityDecision, SecurityDecisionKind, SecurityDisposition, SecurityFailed,
    SecurityNonApproved, SecurityPending, SecurityRejected, SecurityTerminal,
};

/// Closed class of one observational security event.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityEventKind {
    /// One authoritative decision remains incomplete.
    Pending,
    /// Verified ordinary acceptance awaits or received commitment.
    Accepted,
    /// Verified exact-service approval awaits or received commitment.
    Approved,
    /// The exact service is explicitly non-approved.
    NonApproved,
    /// The exact subject was rejected.
    Rejected,
    /// Cancellation completed without acceptance.
    Canceled,
    /// Processing failed without acceptance.
    Failed,
    /// Permanent terminal state forbids further work.
    Terminal,
}

/// One bounded, secret-free duplicate of authoritative security state.
///
/// Construction requires an opaque mandatory outcome, pending value, or
/// authoritative snapshot. The event contains no generation, key handle,
/// peer identity, plaintext, transcript, PSK identity, ticket, ECH inner name,
/// string, byte payload, or stable cross-connection identifier.
///
/// ```compile_fail
/// use brynja_core::{SecurityDecisionKind, SecurityEvent, SecurityEventKind};
/// let forged = SecurityEvent {
///     kind: SecurityEventKind::Accepted,
///     decision: Some(SecurityDecisionKind::Authentication),
///     disposition: None,
///     terminal: None,
/// };
/// ```
///
/// ```compile_fail
/// use brynja_core::SecurityEvent;
/// fn authorize(event: SecurityEvent) {
///     event.commit();
/// }
/// ```
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecurityEvent {
    kind: SecurityEventKind,
    decision: Option<SecurityDecisionKind>,
    disposition: Option<SecurityDisposition>,
    terminal: Option<SecurityTerminal>,
}

impl SecurityEvent {
    const fn outcome(decision: SecurityDecisionKind, disposition: SecurityDisposition) -> Self {
        let kind = match disposition {
            SecurityDisposition::Accepted => SecurityEventKind::Accepted,
            SecurityDisposition::Approved => SecurityEventKind::Approved,
            SecurityDisposition::NonApproved => SecurityEventKind::NonApproved,
            SecurityDisposition::Rejected(_) => SecurityEventKind::Rejected,
            SecurityDisposition::Canceled => SecurityEventKind::Canceled,
            SecurityDisposition::Failed(_) => SecurityEventKind::Failed,
        };
        Self {
            kind,
            decision: Some(decision),
            disposition: Some(disposition),
            terminal: None,
        }
    }

    /// Duplicates an incomplete authoritative decision without consuming it.
    #[must_use]
    pub const fn from_pending<D: SecurityDecision>(pending: &SecurityPending<'_, D>) -> Self {
        Self {
            kind: SecurityEventKind::Pending,
            decision: Some(pending.decision()),
            disposition: None,
            terminal: None,
        }
    }

    /// Duplicates verified acceptance without committing it.
    #[must_use]
    pub const fn from_accepted<D: SecurityDecision>(outcome: &SecurityAccepted<'_, D>) -> Self {
        Self::outcome(outcome.decision(), SecurityDisposition::Accepted)
    }

    /// Duplicates exact-service approval without committing it.
    #[must_use]
    pub const fn from_approved<D: SecurityDecision>(outcome: &SecurityApproved<'_, D>) -> Self {
        Self::outcome(outcome.decision(), SecurityDisposition::Approved)
    }

    /// Duplicates an exact non-approved classification without committing it.
    #[must_use]
    pub const fn from_non_approved<D: SecurityDecision>(
        outcome: &SecurityNonApproved<'_, D>,
    ) -> Self {
        Self::outcome(outcome.decision(), SecurityDisposition::NonApproved)
    }

    /// Duplicates an authoritative rejection without committing it.
    #[must_use]
    pub const fn from_rejected<D: SecurityDecision>(outcome: &SecurityRejected<'_, D>) -> Self {
        Self::outcome(D::KIND, SecurityDisposition::Rejected(outcome.reason()))
    }

    /// Duplicates an authoritative cancellation without committing it.
    #[must_use]
    pub const fn from_canceled<D: SecurityDecision>(outcome: &SecurityCanceled<'_, D>) -> Self {
        Self::outcome(outcome.decision(), SecurityDisposition::Canceled)
    }

    /// Duplicates an authoritative failure without committing it.
    #[must_use]
    pub const fn from_failed<D: SecurityDecision>(outcome: &SecurityFailed<'_, D>) -> Self {
        Self::outcome(D::KIND, SecurityDisposition::Failed(outcome.reason()))
    }

    /// Duplicates a non-ready authoritative snapshot.
    ///
    /// Ready state has no security result to report and returns `None`.
    #[must_use]
    pub const fn from_snapshot(snapshot: SecurityAuthoritySnapshot) -> Option<Self> {
        match snapshot.state() {
            SecurityAuthorityState::Ready => None,
            SecurityAuthorityState::Pending(decision) => Some(Self {
                kind: SecurityEventKind::Pending,
                decision: Some(decision),
                disposition: None,
                terminal: None,
            }),
            SecurityAuthorityState::AwaitingCommit {
                decision,
                disposition,
            } => Some(Self::outcome(decision, disposition)),
            SecurityAuthorityState::Terminal => match snapshot.terminal() {
                Some(terminal) => Some(Self {
                    kind: SecurityEventKind::Terminal,
                    decision: None,
                    disposition: None,
                    terminal: Some(terminal),
                }),
                None => None,
            },
        }
    }

    /// Returns the closed event class.
    #[must_use]
    pub const fn kind(self) -> SecurityEventKind {
        self.kind
    }

    /// Returns the exact decision domain duplicated by this event.
    #[must_use]
    pub const fn decision(self) -> Option<SecurityDecisionKind> {
        self.decision
    }

    /// Returns the exact validated disposition, when this is an outcome event.
    #[must_use]
    pub const fn disposition(self) -> Option<SecurityDisposition> {
        self.disposition
    }

    /// Returns the permanent reason, only for terminal events.
    #[must_use]
    pub const fn terminal(self) -> Option<SecurityTerminal> {
        self.terminal
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ProviderFailureKind, SecurityFailureKind, SecurityRejection};
    use core::fmt::Write;

    struct FormatSink;

    impl core::fmt::Write for FormatSink {
        fn write_str(&mut self, _value: &str) -> core::fmt::Result {
            Ok(())
        }
    }

    #[test]
    fn every_closed_variant_is_format_safe() {
        let dispositions = [
            SecurityDisposition::Accepted,
            SecurityDisposition::Approved,
            SecurityDisposition::NonApproved,
            SecurityDisposition::Rejected(SecurityRejection::Authentication),
            SecurityDisposition::Canceled,
            SecurityDisposition::Failed(SecurityFailureKind::Provider(
                ProviderFailureKind::InvalidOutput,
            )),
        ];
        for disposition in dispositions {
            assert!(
                write!(
                    FormatSink,
                    "{:?}",
                    SecurityEvent::outcome(SecurityDecisionKind::Authentication, disposition)
                )
                .is_ok()
            );
        }
        let pending = SecurityEvent {
            kind: SecurityEventKind::Pending,
            decision: Some(SecurityDecisionKind::Authentication),
            disposition: None,
            terminal: None,
        };
        assert!(write!(FormatSink, "{pending:?}").is_ok());
        let terminal = SecurityEvent {
            kind: SecurityEventKind::Terminal,
            decision: None,
            disposition: None,
            terminal: Some(SecurityTerminal::Integrity),
        };
        assert!(write!(FormatSink, "{terminal:?}").is_ok());
    }
}
