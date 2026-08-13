//! Caller-owned authoritative decision state and exhaustive results.

use core::{cell::Cell, marker::PhantomData};

use crate::ProviderFailureKind;

use super::{SecurityDecision, SecurityDecisionKind, ServiceApprovalDecision};

/// Authoritative engine state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityAuthorityState {
    /// No decision is in progress.
    Ready,
    /// One exact decision is incomplete.
    Pending(SecurityDecisionKind),
    /// A terminal failure permanently forbids further decisions.
    Terminal,
}

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
    /// A self-test reported failure.
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
/// This value is input to the authority state machine, not an informational
/// event. `Approved` and `NonApproved` are valid only for
/// [`ServiceApprovalDecision`]; misuse fails terminally.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[must_use = "a security resolution must be committed to authoritative state"]
pub enum SecurityResolution {
    /// Work remains incomplete.
    Pending,
    /// The exact non-approval decision succeeded.
    Accepted,
    /// The exact service is approved.
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

const fn rejection_matches_domain(
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

const fn failure_matches_domain(
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

#[derive(Clone, Copy)]
struct AuthorityRecord {
    state: SecurityAuthorityState,
    generation: u64,
    terminal: Option<SecurityTerminal>,
}

/// Informational snapshot of authoritative state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct SecurityAuthoritySnapshot {
    state: SecurityAuthorityState,
    generation: u64,
    terminal: Option<SecurityTerminal>,
}

impl SecurityAuthoritySnapshot {
    /// Returns the exact authoritative state.
    #[must_use]
    pub const fn state(self) -> SecurityAuthorityState {
        self.state
    }

    /// Returns the monotonic transition generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the first permanent terminal reason.
    #[must_use]
    pub const fn terminal(self) -> Option<SecurityTerminal> {
        self.terminal
    }
}

/// Failure to begin one authoritative decision.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityAuthorityError {
    /// Another exact decision remains incomplete.
    Busy(SecurityDecisionKind),
    /// Permanent terminal state forbids further decisions.
    Terminal(SecurityTerminal),
}

/// Caller-owned, allocation-free authoritative security state.
///
/// This type does not implement a protocol engine or provider effect.
pub struct SecurityAuthority {
    record: Cell<AuthorityRecord>,
}

impl SecurityAuthority {
    /// Creates ready state at generation one.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            record: Cell::new(AuthorityRecord {
                state: SecurityAuthorityState::Ready,
                generation: 1,
                terminal: None,
            }),
        }
    }

    /// Returns a secret-free informational snapshot.
    #[must_use]
    pub fn snapshot(&self) -> SecurityAuthoritySnapshot {
        let record = self.record.get();
        SecurityAuthoritySnapshot {
            state: record.state,
            generation: record.generation,
            terminal: record.terminal,
        }
    }

    /// Begins one exact typed decision and returns its mandatory pending value.
    pub fn begin<D: SecurityDecision>(
        &self,
    ) -> Result<SecurityPending<'_, D>, SecurityAuthorityError> {
        let record = self.record.get();
        match record.state {
            SecurityAuthorityState::Ready => {}
            SecurityAuthorityState::Pending(kind) => {
                return Err(SecurityAuthorityError::Busy(kind));
            }
            SecurityAuthorityState::Terminal => {
                return Err(SecurityAuthorityError::Terminal(
                    record
                        .terminal
                        .unwrap_or(SecurityTerminal::ContractInvariant),
                ));
            }
        }
        let Some(generation) = record.generation.checked_add(1) else {
            self.fail_terminal(SecurityTerminal::GenerationExhausted);
            return Err(SecurityAuthorityError::Terminal(
                SecurityTerminal::GenerationExhausted,
            ));
        };
        self.record.set(AuthorityRecord {
            state: SecurityAuthorityState::Pending(D::KIND),
            generation,
            terminal: None,
        });
        Ok(SecurityPending::new(self, generation))
    }

    pub(super) fn fail_terminal(&self, reason: SecurityTerminal) {
        let current = self.record.get();
        if matches!(current.state, SecurityAuthorityState::Terminal) {
            return;
        }
        let generation = current
            .generation
            .checked_add(1)
            .unwrap_or(current.generation);
        let terminal = if generation == current.generation {
            SecurityTerminal::GenerationExhausted
        } else {
            reason
        };
        self.record.set(AuthorityRecord {
            state: SecurityAuthorityState::Terminal,
            generation,
            terminal: Some(terminal),
        });
    }

    fn resolve<D: SecurityDecision>(
        &self,
        generation: u64,
        resolution: SecurityResolution,
    ) -> SecurityOutcome<'_, D> {
        let current = self.record.get();
        if current.state != SecurityAuthorityState::Pending(D::KIND)
            || current.generation != generation
        {
            self.fail_terminal(SecurityTerminal::ContractInvariant);
            return SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND));
        }
        if matches!(
            resolution,
            SecurityResolution::Approved | SecurityResolution::NonApproved
        ) && D::KIND != ServiceApprovalDecision::KIND
        {
            self.fail_terminal(SecurityTerminal::ContractInvariant);
            return SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND));
        }
        if D::KIND == ServiceApprovalDecision::KIND
            && matches!(resolution, SecurityResolution::Accepted)
        {
            self.fail_terminal(SecurityTerminal::ContractInvariant);
            return SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND));
        }
        if D::KIND == SecurityDecisionKind::TerminalTransition
            && !matches!(
                resolution,
                SecurityResolution::Pending | SecurityResolution::Terminal(_)
            )
        {
            self.fail_terminal(SecurityTerminal::ContractInvariant);
            return SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND));
        }
        if let SecurityResolution::Rejected(reason) = resolution
            && !rejection_matches_domain(D::KIND, reason)
        {
            self.fail_terminal(SecurityTerminal::ContractInvariant);
            return SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND));
        }
        if let SecurityResolution::Failed(reason) = resolution
            && !failure_matches_domain(D::KIND, reason)
        {
            self.fail_terminal(SecurityTerminal::ContractInvariant);
            return SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND));
        }
        match resolution {
            SecurityResolution::Pending => {
                SecurityOutcome::Pending(SecurityPending::new(self, generation))
            }
            SecurityResolution::Terminal(reason) => {
                self.fail_terminal(reason);
                SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND))
            }
            other => {
                let Some(next) = generation.checked_add(1) else {
                    self.fail_terminal(SecurityTerminal::GenerationExhausted);
                    return SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND));
                };
                self.record.set(AuthorityRecord {
                    state: SecurityAuthorityState::Ready,
                    generation: next,
                    terminal: None,
                });
                let receipt = SecurityReceipt::new(self, D::KIND);
                match other {
                    SecurityResolution::Accepted => SecurityOutcome::Accepted(receipt),
                    SecurityResolution::Approved => SecurityOutcome::Approved(receipt),
                    SecurityResolution::NonApproved => SecurityOutcome::NonApproved(receipt),
                    SecurityResolution::Rejected(reason) => {
                        SecurityOutcome::Rejected(receipt, reason)
                    }
                    SecurityResolution::Canceled => SecurityOutcome::Canceled(receipt),
                    SecurityResolution::Failed(reason) => SecurityOutcome::Failed(receipt, reason),
                    SecurityResolution::Pending | SecurityResolution::Terminal(_) => {
                        self.fail_terminal(SecurityTerminal::ContractInvariant);
                        SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND))
                    }
                }
            }
        }
    }
}

impl Default for SecurityAuthority {
    fn default() -> Self {
        Self::new()
    }
}

/// Affine ownership of one incomplete exact decision.
///
/// ```compile_fail
/// use brynja_core::{AuthenticationDecision, SecurityPending};
/// fn require_clone<T: Clone>() {}
/// require_clone::<SecurityPending<'static, AuthenticationDecision>>();
/// ```
///
/// ```compile_fail
/// use brynja_core::{AuthenticationDecision, SecurityPending};
/// fn require_send<T: Send>() {}
/// require_send::<SecurityPending<'static, AuthenticationDecision>>();
/// ```
#[must_use = "pending security work must be resolved or remain visibly incomplete"]
pub struct SecurityPending<'authority, D: SecurityDecision> {
    authority: &'authority SecurityAuthority,
    generation: u64,
    decision: PhantomData<D>,
    thread_bound: PhantomData<*mut ()>,
}

impl<'authority, D: SecurityDecision> SecurityPending<'authority, D> {
    pub(super) const fn new(authority: &'authority SecurityAuthority, generation: u64) -> Self {
        Self {
            authority,
            generation,
            decision: PhantomData,
            thread_bound: PhantomData,
        }
    }

    /// Returns the exact typed decision discriminant.
    #[must_use]
    pub const fn decision(&self) -> SecurityDecisionKind {
        D::KIND
    }

    /// Returns the generation bound to this incomplete decision.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Consumes the incomplete value into one mandatory authoritative outcome.
    pub fn resolve(self, resolution: SecurityResolution) -> SecurityOutcome<'authority, D> {
        self.authority.resolve::<D>(self.generation, resolution)
    }

    pub(super) const fn authority(&self) -> &'authority SecurityAuthority {
        self.authority
    }
}

/// Non-forgeable receipt for one completed authoritative transition.
pub struct SecurityReceipt<'authority, D: SecurityDecision> {
    authority: &'authority SecurityAuthority,
    decision: SecurityDecisionKind,
    generation: u64,
    marker: PhantomData<D>,
    thread_bound: PhantomData<*mut ()>,
}

impl<'authority, D: SecurityDecision> SecurityReceipt<'authority, D> {
    pub(super) fn new(
        authority: &'authority SecurityAuthority,
        decision: SecurityDecisionKind,
    ) -> Self {
        Self {
            authority,
            decision,
            generation: authority.snapshot().generation(),
            marker: PhantomData,
            thread_bound: PhantomData,
        }
    }

    /// Returns the exact decision that completed.
    #[must_use]
    pub const fn decision(&self) -> SecurityDecisionKind {
        self.decision
    }

    /// Returns the authoritative completion generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns whether this receipt belongs to the supplied authority.
    #[must_use]
    pub fn belongs_to(&self, authority: &SecurityAuthority) -> bool {
        core::ptr::eq(self.authority, authority)
    }
}

/// Exhaustive mandatory result of one exact security decision.
#[must_use = "the authoritative security outcome must govern the next state"]
pub enum SecurityOutcome<'authority, D: SecurityDecision> {
    /// The exact ordinary decision succeeded.
    Accepted(SecurityReceipt<'authority, D>),
    /// The exact service is approved.
    Approved(SecurityReceipt<'authority, D>),
    /// The exact service is explicitly non-approved.
    NonApproved(SecurityReceipt<'authority, D>),
    /// The subject was authoritatively rejected.
    Rejected(SecurityReceipt<'authority, D>, SecurityRejection),
    /// Work remains incomplete and retains affine authority.
    Pending(SecurityPending<'authority, D>),
    /// Cancellation completed without acceptance.
    Canceled(SecurityReceipt<'authority, D>),
    /// Processing failed without acceptance.
    Failed(SecurityReceipt<'authority, D>, SecurityFailureKind),
    /// Permanent terminal state forbids further work.
    Terminal(SecurityReceipt<'authority, D>),
}

/// Type alias for the cancellation result receipt.
pub type SecurityCanceled<'authority, D> = SecurityReceipt<'authority, D>;

/// Type alias for a non-terminal failure result receipt and reason.
pub type SecurityFailure<'authority, D> = (SecurityReceipt<'authority, D>, SecurityFailureKind);
