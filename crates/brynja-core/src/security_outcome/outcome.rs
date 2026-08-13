//! Opaque disposition-bound outcomes awaiting authoritative commitment.

use core::marker::PhantomData;

use super::{
    SecurityAuthority, SecurityDecision, SecurityDisposition, SecurityFailureKind, SecurityPending,
    SecurityReceipt, SecurityRejection,
};

struct Completion<'authority, D: SecurityDecision> {
    authority: &'authority SecurityAuthority,
    generation: u64,
    disposition: SecurityDisposition,
    armed: bool,
    decision: PhantomData<D>,
    thread_bound: PhantomData<*mut ()>,
}

impl<'authority, D: SecurityDecision> Completion<'authority, D> {
    const fn new(
        authority: &'authority SecurityAuthority,
        generation: u64,
        disposition: SecurityDisposition,
    ) -> Self {
        Self {
            authority,
            generation,
            disposition,
            armed: true,
            decision: PhantomData,
            thread_bound: PhantomData,
        }
    }

    const fn decision(&self) -> super::SecurityDecisionKind {
        D::KIND
    }

    const fn generation(&self) -> u64 {
        self.generation
    }

    fn commit(mut self) -> SecurityReceipt<'authority, D> {
        let receipt = self
            .authority
            .commit::<D>(self.generation, self.disposition);
        self.armed = false;
        receipt
    }
}

impl<D: SecurityDecision> Drop for Completion<'_, D> {
    fn drop(&mut self) {
        if self.armed {
            self.authority
                .fail_terminal(super::SecurityTerminal::OutcomeAbandoned);
        }
    }
}

/// Opaque verified acceptance awaiting explicit commitment.
#[must_use = "an accepted result must govern engine state"]
pub struct SecurityAccepted<'authority, D: SecurityDecision> {
    completion: Completion<'authority, D>,
}

impl<'authority, D: SecurityDecision> SecurityAccepted<'authority, D> {
    pub(super) const fn new(authority: &'authority SecurityAuthority, generation: u64) -> Self {
        Self {
            completion: Completion::new(authority, generation, SecurityDisposition::Accepted),
        }
    }

    /// Returns the exact typed decision discriminant.
    #[must_use]
    pub const fn decision(&self) -> super::SecurityDecisionKind {
        self.completion.decision()
    }

    /// Returns the generation bound to this outcome.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.completion.generation()
    }

    /// Commits this exact acceptance and unlocks the authority.
    pub fn commit(self) -> SecurityReceipt<'authority, D> {
        self.completion.commit()
    }
}

/// Opaque exact non-approved classification awaiting explicit commitment.
#[must_use = "a non-approved result must govern engine state"]
pub struct SecurityNonApproved<'authority, D: SecurityDecision> {
    completion: Completion<'authority, D>,
}

impl<'authority, D: SecurityDecision> SecurityNonApproved<'authority, D> {
    pub(super) const fn new(authority: &'authority SecurityAuthority, generation: u64) -> Self {
        Self {
            completion: Completion::new(authority, generation, SecurityDisposition::NonApproved),
        }
    }

    /// Returns the exact typed decision discriminant.
    #[must_use]
    pub const fn decision(&self) -> super::SecurityDecisionKind {
        self.completion.decision()
    }

    /// Returns the generation bound to this outcome.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.completion.generation()
    }

    /// Commits this exact classification and unlocks the authority.
    pub fn commit(self) -> SecurityReceipt<'authority, D> {
        self.completion.commit()
    }
}

/// Opaque exact cancellation awaiting explicit commitment.
#[must_use = "a canceled result must govern engine state"]
pub struct SecurityCanceled<'authority, D: SecurityDecision> {
    completion: Completion<'authority, D>,
}

impl<'authority, D: SecurityDecision> SecurityCanceled<'authority, D> {
    pub(super) const fn new(authority: &'authority SecurityAuthority, generation: u64) -> Self {
        Self {
            completion: Completion::new(authority, generation, SecurityDisposition::Canceled),
        }
    }

    /// Returns the exact typed decision discriminant.
    #[must_use]
    pub const fn decision(&self) -> super::SecurityDecisionKind {
        self.completion.decision()
    }

    /// Returns the generation bound to this outcome.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.completion.generation()
    }

    /// Commits this exact cancellation and unlocks the authority.
    pub fn commit(self) -> SecurityReceipt<'authority, D> {
        self.completion.commit()
    }
}

/// Opaque verified exact-service approval awaiting explicit commitment.
///
/// No constructor exists until a future sealed exact-service proof is
/// implemented and reviewed.
///
/// ```compile_fail
/// use brynja_core::{SecurityApproved, SecurityNonApproved, ServiceApprovalDecision};
/// fn launder<'a>(value: SecurityNonApproved<'a, ServiceApprovalDecision>)
///     -> SecurityApproved<'a, ServiceApprovalDecision>
/// {
///     value
/// }
/// ```
#[must_use = "an approved service must govern engine state"]
pub struct SecurityApproved<'authority, D: SecurityDecision> {
    completion: Completion<'authority, D>,
}

impl<'authority, D: SecurityDecision> SecurityApproved<'authority, D> {
    /// Returns the exact typed decision discriminant.
    #[must_use]
    pub const fn decision(&self) -> super::SecurityDecisionKind {
        self.completion.decision()
    }

    /// Returns the generation bound to this outcome.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.completion.generation()
    }

    /// Commits this exact approval and unlocks the authority.
    pub fn commit(self) -> SecurityReceipt<'authority, D> {
        self.completion.commit()
    }
}

/// Opaque rejection retaining its authority-validated reason.
///
/// ```compile_fail
/// use brynja_core::{AuthenticationDecision, SecurityOutcome, SecurityRejected};
/// fn launder<'a>(value: SecurityRejected<'a, AuthenticationDecision>)
///     -> SecurityOutcome<'a, AuthenticationDecision>
/// {
///     SecurityOutcome::Accepted(value)
/// }
/// ```
///
/// ```compile_fail
/// use brynja_core::{AuthenticationDecision, SecurityRejected, SecurityRejection};
/// fn substitute(mut value: SecurityRejected<'_, AuthenticationDecision>) {
///     value.reason = SecurityRejection::Policy;
/// }
/// ```
#[must_use = "an authoritative rejection must govern engine state"]
pub struct SecurityRejected<'authority, D: SecurityDecision> {
    completion: Completion<'authority, D>,
    reason: SecurityRejection,
}

impl<'authority, D: SecurityDecision> SecurityRejected<'authority, D> {
    pub(super) const fn new(
        authority: &'authority SecurityAuthority,
        generation: u64,
        reason: SecurityRejection,
    ) -> Self {
        Self {
            completion: Completion::new(
                authority,
                generation,
                SecurityDisposition::Rejected(reason),
            ),
            reason,
        }
    }

    /// Returns the exact authority-validated rejection reason.
    #[must_use]
    pub const fn reason(&self) -> SecurityRejection {
        self.reason
    }

    /// Commits this exact rejection and unlocks the authority.
    pub fn commit(self) -> SecurityReceipt<'authority, D> {
        self.completion.commit()
    }
}

/// Opaque failure retaining its authority-validated reason.
///
/// ```compile_fail
/// use brynja_core::{AuthenticationDecision, SecurityFailed, SecurityRejected};
/// fn cross<'a>(value: SecurityRejected<'a, AuthenticationDecision>)
///     -> SecurityFailed<'a, AuthenticationDecision>
/// {
///     value
/// }
/// ```
#[must_use = "an authoritative failure must govern engine state"]
pub struct SecurityFailed<'authority, D: SecurityDecision> {
    completion: Completion<'authority, D>,
    reason: SecurityFailureKind,
}

impl<'authority, D: SecurityDecision> SecurityFailed<'authority, D> {
    pub(super) const fn new(
        authority: &'authority SecurityAuthority,
        generation: u64,
        reason: SecurityFailureKind,
    ) -> Self {
        Self {
            completion: Completion::new(authority, generation, SecurityDisposition::Failed(reason)),
            reason,
        }
    }

    /// Returns the exact authority-validated failure reason.
    #[must_use]
    pub const fn reason(&self) -> SecurityFailureKind {
        self.reason
    }

    /// Commits this exact failure and unlocks the authority.
    pub fn commit(self) -> SecurityReceipt<'authority, D> {
        self.completion.commit()
    }
}

/// Exhaustive mandatory result of one exact security decision.
#[must_use = "the authoritative security outcome must govern the next state"]
pub enum SecurityOutcome<'authority, D: SecurityDecision> {
    /// A verified ordinary decision succeeded and awaits explicit commitment.
    Accepted(SecurityAccepted<'authority, D>),
    /// A verified exact service is approved and awaits explicit commitment.
    Approved(SecurityApproved<'authority, D>),
    /// The exact service is explicitly non-approved.
    NonApproved(SecurityNonApproved<'authority, D>),
    /// The subject was authoritatively rejected.
    Rejected(SecurityRejected<'authority, D>),
    /// Work remains incomplete and retains affine authority.
    Pending(SecurityPending<'authority, D>),
    /// Cancellation completed without acceptance.
    Canceled(SecurityCanceled<'authority, D>),
    /// Processing failed without acceptance.
    Failed(SecurityFailed<'authority, D>),
    /// Permanent terminal state forbids further work.
    Terminal(SecurityReceipt<'authority, D>),
}

/// Compatibility name for a typed non-terminal failure outcome.
pub type SecurityFailure<'authority, D> = SecurityFailed<'authority, D>;
