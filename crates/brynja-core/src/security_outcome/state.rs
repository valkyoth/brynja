//! Caller-owned authoritative decision state and exhaustive results.

use core::{cell::Cell, marker::PhantomData};

use super::outcome::{
    SecurityAccepted, SecurityCanceled, SecurityFailed, SecurityNonApproved, SecurityOutcome,
    SecurityRejected,
};
use super::resolution::{failure_matches_domain, rejection_matches_domain};
use super::{
    SecurityDecision, SecurityDecisionKind, SecurityDisposition, SecurityFailureKind,
    SecurityResolution, SecurityTerminal, ServiceApprovalDecision,
};

/// Authoritative engine state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum SecurityAuthorityState {
    /// No decision is in progress.
    Ready,
    /// One exact decision is incomplete.
    Pending(SecurityDecisionKind),
    /// One resolved outcome must still be committed by the protocol engine.
    AwaitingCommit {
        /// Exact decision awaiting commitment.
        decision: SecurityDecisionKind,
        /// Exact authority-validated disposition awaiting commitment.
        disposition: SecurityDisposition,
    },
    /// A terminal failure permanently forbids further decisions.
    Terminal,
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
            SecurityAuthorityState::AwaitingCommit { decision, .. } => {
                return Err(SecurityAuthorityError::Busy(decision));
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
        positive_authorized: bool,
    ) -> SecurityOutcome<'_, D> {
        let current = self.record.get();
        if current.state != SecurityAuthorityState::Pending(D::KIND)
            || current.generation != generation
        {
            self.fail_terminal(SecurityTerminal::ContractInvariant);
            return SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND));
        }
        if matches!(resolution, SecurityResolution::Approved)
            || (matches!(resolution, SecurityResolution::Accepted) && !positive_authorized)
        {
            self.fail_terminal(SecurityTerminal::ContractInvariant);
            return SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND));
        }
        if matches!(resolution, SecurityResolution::NonApproved)
            && D::KIND != ServiceApprovalDecision::KIND
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
        if D::KIND == SecurityDecisionKind::SelfTest
            && matches!(
                resolution,
                SecurityResolution::Failed(SecurityFailureKind::SelfTest)
            )
        {
            self.fail_terminal(SecurityTerminal::Integrity);
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
                let disposition = match other {
                    SecurityResolution::Accepted => SecurityDisposition::Accepted,
                    SecurityResolution::NonApproved => SecurityDisposition::NonApproved,
                    SecurityResolution::Rejected(reason) => SecurityDisposition::Rejected(reason),
                    SecurityResolution::Canceled => SecurityDisposition::Canceled,
                    SecurityResolution::Failed(reason) => SecurityDisposition::Failed(reason),
                    SecurityResolution::Approved
                    | SecurityResolution::Pending
                    | SecurityResolution::Terminal(_) => {
                        self.fail_terminal(SecurityTerminal::ContractInvariant);
                        return SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND));
                    }
                };
                self.record.set(AuthorityRecord {
                    state: SecurityAuthorityState::AwaitingCommit {
                        decision: D::KIND,
                        disposition,
                    },
                    generation,
                    terminal: None,
                });
                match other {
                    SecurityResolution::Accepted => {
                        SecurityOutcome::Accepted(SecurityAccepted::new(self, generation))
                    }
                    SecurityResolution::NonApproved => {
                        SecurityOutcome::NonApproved(SecurityNonApproved::new(self, generation))
                    }
                    SecurityResolution::Rejected(reason) => {
                        SecurityOutcome::Rejected(SecurityRejected::new(self, generation, reason))
                    }
                    SecurityResolution::Canceled => {
                        SecurityOutcome::Canceled(SecurityCanceled::new(self, generation))
                    }
                    SecurityResolution::Failed(reason) => {
                        SecurityOutcome::Failed(SecurityFailed::new(self, generation, reason))
                    }
                    SecurityResolution::Approved
                    | SecurityResolution::Pending
                    | SecurityResolution::Terminal(_) => {
                        self.fail_terminal(SecurityTerminal::ContractInvariant);
                        SecurityOutcome::Terminal(SecurityReceipt::new(self, D::KIND))
                    }
                }
            }
        }
    }

    pub(super) fn commit<D: SecurityDecision>(
        &self,
        generation: u64,
        disposition: SecurityDisposition,
    ) -> SecurityReceipt<'_, D> {
        let current = self.record.get();
        if current.state
            != (SecurityAuthorityState::AwaitingCommit {
                decision: D::KIND,
                disposition,
            })
            || current.generation != generation
        {
            self.fail_terminal(SecurityTerminal::ContractInvariant);
            return SecurityReceipt::new(self, D::KIND);
        }
        self.record.set(AuthorityRecord {
            state: SecurityAuthorityState::Ready,
            generation,
            terminal: None,
        });
        SecurityReceipt::new(self, D::KIND)
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
    armed: bool,
    decision: PhantomData<D>,
    thread_bound: PhantomData<*mut ()>,
}

impl<'authority, D: SecurityDecision> SecurityPending<'authority, D> {
    pub(super) const fn new(authority: &'authority SecurityAuthority, generation: u64) -> Self {
        Self {
            authority,
            generation,
            armed: true,
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
    pub fn resolve(mut self, resolution: SecurityResolution) -> SecurityOutcome<'authority, D> {
        self.armed = false;
        self.authority
            .resolve::<D>(self.generation, resolution, false)
    }

    pub(super) fn resolve_verified_accepted(mut self) -> SecurityOutcome<'authority, D> {
        self.armed = false;
        self.authority
            .resolve::<D>(self.generation, SecurityResolution::Accepted, true)
    }

    pub(super) const fn authority(&self) -> &'authority SecurityAuthority {
        self.authority
    }
}

impl<D: SecurityDecision> Drop for SecurityPending<'_, D> {
    fn drop(&mut self) {
        if self.armed {
            self.authority
                .fail_terminal(SecurityTerminal::DecisionAbandoned);
        }
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
