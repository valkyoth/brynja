//! Closed resolution, rejection, failure, and terminal categories.

use crate::ProviderFailureKind;

use super::SecurityDecisionKind;

/// Closed rejection reasons that carry no peer-controlled text or secret.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityRejection {
    /// The requested capability or combination is unsupported.
    Unsupported,
    /// Mandatory local policy rejected the operation.
    Policy,
    /// Authentication did not succeed.
    Authentication,
    /// Replay or duplicate-use policy rejected the operation.
    Replay,
    /// Amplification limits rejected the operation.
    Amplification,
    /// A ticket was invalid or inadmissible.
    Ticket,
    /// A pre-shared key was invalid or inadmissible.
    Psk,
    /// Early data was not admitted.
    EarlyData,
    /// Encrypted ClientHello was not admitted.
    Ech,
}

/// Closed non-terminal failure reasons.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityFailureKind {
    /// A self-test reported failure and will permanently fail the authority.
    SelfTest,
    /// A provider returned a closed failure category.
    Provider(ProviderFailureKind),
    /// A bounded resource, sequence, or work domain was exhausted.
    Exhaustion,
    /// Authentication processing failed without producing acceptance.
    Authentication,
    /// Key lifecycle processing failed before authoritative completion.
    KeyLifecycle,
    /// Local policy evaluation failed closed.
    Policy,
}

/// Closed permanent terminal reasons.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityTerminal {
    /// Internal state or token binding was inconsistent.
    ContractInvariant,
    /// An incomplete decision was abandoned without an authoritative result.
    DecisionAbandoned,
    /// A resolved mandatory outcome was discarded before it governed state.
    OutcomeAbandoned,
    /// A catastrophic provider failure requires permanent shutdown.
    Provider,
    /// Mandatory external-key destruction did not complete.
    ExternalKeyDestruction,
    /// A security-relevant generation was exhausted.
    GenerationExhausted,
    /// Integrity or mandatory self-test failure requires shutdown.
    Integrity,
    /// Mandatory policy requires permanent shutdown.
    Policy,
}

/// Engine-supplied resolution of one pending decision.
///
/// This input cannot establish positive authorization by itself. `Accepted`
/// and `Approved` fail terminally until reviewed execution supplies a
/// sealed, subject-bound proof. Negative and incomplete resolutions remain
/// caller-selectable so protocol engines can fail closed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use = "a security resolution must be committed to authoritative state"]
pub enum SecurityResolution {
    /// Work remains incomplete.
    Pending,
    /// Reserved for separately verified positive execution.
    Accepted,
    /// Reserved for a complete exact-service approval proof.
    Approved,
    /// The exact service is explicitly non-approved.
    NonApproved,
    /// The decision rejected its subject.
    Rejected(SecurityRejection),
    /// Cancellation completed without acceptance.
    Canceled,
    /// Processing failed without acceptance.
    Failed(SecurityFailureKind),
    /// Processing permanently failed the authority.
    Terminal(SecurityTerminal),
}

pub(super) const fn rejection_matches_domain(
    decision: SecurityDecisionKind,
    reason: SecurityRejection,
) -> bool {
    matches!(
        (decision, reason),
        (
            SecurityDecisionKind::ProtocolSelection
                | SecurityDecisionKind::ProfileSelection
                | SecurityDecisionKind::ServiceApproval
                | SecurityDecisionKind::Provider,
            SecurityRejection::Unsupported
        ) | (SecurityDecisionKind::Policy, SecurityRejection::Policy)
            | (
                SecurityDecisionKind::Authentication,
                SecurityRejection::Authentication
            )
            | (SecurityDecisionKind::AntiReplay, SecurityRejection::Replay)
            | (
                SecurityDecisionKind::Amplification,
                SecurityRejection::Amplification
            )
            | (SecurityDecisionKind::Ticket, SecurityRejection::Ticket)
            | (SecurityDecisionKind::Psk, SecurityRejection::Psk)
            | (
                SecurityDecisionKind::EarlyData,
                SecurityRejection::EarlyData
            )
            | (SecurityDecisionKind::Ech, SecurityRejection::Ech)
    )
}

pub(super) const fn failure_matches_domain(
    decision: SecurityDecisionKind,
    reason: SecurityFailureKind,
) -> bool {
    matches!(
        (decision, reason),
        (
            SecurityDecisionKind::SelfTest,
            SecurityFailureKind::SelfTest
        ) | (
            SecurityDecisionKind::Provider,
            SecurityFailureKind::Provider(_)
        ) | (
            SecurityDecisionKind::Exhaustion,
            SecurityFailureKind::Exhaustion
        ) | (
            SecurityDecisionKind::Authentication,
            SecurityFailureKind::Authentication
        ) | (
            SecurityDecisionKind::KeyLifecycle,
            SecurityFailureKind::KeyLifecycle
        ) | (SecurityDecisionKind::Policy, SecurityFailureKind::Policy)
    )
}
