//! Mandatory external-key destruction completion.

use core::marker::PhantomData;

use crate::{DestructionTarget, ProviderFailureKind};

use super::{
    KeyLifecycleDecision, SecurityAuthority, SecurityAuthorityError, SecurityOutcome,
    SecurityPending, SecurityReceipt, SecurityResolution, SecurityTerminal,
};

/// Failure to obtain or submit external-key destruction authority.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExternalKeyDestructionError {
    /// The authority could not begin the key-lifecycle decision.
    Authority(SecurityAuthorityError),
    /// A destruction token was already issued for this transition.
    TokenAlreadyIssued,
}

/// Closed external-key destruction failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub enum ExternalKeyDestructionFailure {
    /// The provider rejected or failed destruction.
    Provider(ProviderFailureKind),
}

/// Single-consumption authority to complete one external-store destruction.
///
/// Returning completion is a security assertion that the external key is no
/// longer usable and every required durable provider operation has completed.
///
/// ```compile_fail
/// use brynja_core::ExternalKeyDestructionToken;
/// fn duplicate(token: ExternalKeyDestructionToken<'_>) {
///     let _ = token.clone();
/// }
/// ```
#[must_use = "external-key destruction authority must be consumed exactly once"]
pub struct ExternalKeyDestructionToken<'authority> {
    authority: &'authority SecurityAuthority,
    generation: u64,
    thread_bound: PhantomData<*mut ()>,
}

impl<'authority> ExternalKeyDestructionToken<'authority> {
    /// Returns the exact mandatory destruction target.
    #[must_use]
    pub const fn target(&self) -> DestructionTarget {
        DestructionTarget::ExternalStore
    }

    /// Asserts that mandatory destruction completed and consumes the token.
    pub const fn complete(self) -> ExternalKeyDestructionOutcome<'authority> {
        ExternalKeyDestructionOutcome::Complete(ExternalKeyDestroyed {
            authority: self.authority,
            generation: self.generation,
            thread_bound: PhantomData,
        })
    }

    /// Reports provider destruction failure and consumes the token.
    pub const fn fail(
        self,
        kind: ProviderFailureKind,
    ) -> ExternalKeyDestructionOutcome<'authority> {
        ExternalKeyDestructionOutcome::Failed {
            authority: self.authority,
            generation: self.generation,
            reason: ExternalKeyDestructionFailure::Provider(kind),
        }
    }
}

/// Non-forgeable proof of completed external-key destruction.
#[must_use = "external-key completion must be submitted to the authority"]
pub struct ExternalKeyDestroyed<'authority> {
    authority: &'authority SecurityAuthority,
    generation: u64,
    thread_bound: PhantomData<*mut ()>,
}

/// Mandatory result returned by the external-key destruction effect.
#[must_use = "external-key destruction outcome must be committed"]
pub enum ExternalKeyDestructionOutcome<'authority> {
    /// External-key destruction completed.
    Complete(ExternalKeyDestroyed<'authority>),
    /// External-key destruction failed.
    Failed {
        /// Exact authority that issued the token.
        authority: &'authority SecurityAuthority,
        /// Exact pending generation.
        generation: u64,
        /// Closed failure reason.
        reason: ExternalKeyDestructionFailure,
    },
}

/// Affine external-key lifecycle requiring a destruction-token outcome.
#[must_use = "external-key destruction must complete or fail terminally"]
pub struct ExternalKeyDestruction<'authority> {
    authority: &'authority SecurityAuthority,
    pending: Option<SecurityPending<'authority, KeyLifecycleDecision>>,
    token_issued: bool,
}

impl<'authority> ExternalKeyDestruction<'authority> {
    /// Begins one external-key destruction transition.
    pub fn begin(
        authority: &'authority SecurityAuthority,
    ) -> Result<Self, ExternalKeyDestructionError> {
        let pending = authority
            .begin::<KeyLifecycleDecision>()
            .map_err(ExternalKeyDestructionError::Authority)?;
        Ok(Self {
            authority,
            pending: Some(pending),
            token_issued: false,
        })
    }

    /// Issues the exact single-consumption provider destruction authority.
    pub fn destruction_token(
        &mut self,
    ) -> Result<ExternalKeyDestructionToken<'authority>, ExternalKeyDestructionError> {
        if self.token_issued {
            return Err(ExternalKeyDestructionError::TokenAlreadyIssued);
        }
        let Some(pending) = self.pending.as_ref() else {
            return Err(ExternalKeyDestructionError::Authority(
                SecurityAuthorityError::Terminal(SecurityTerminal::ContractInvariant),
            ));
        };
        self.token_issued = true;
        Ok(ExternalKeyDestructionToken {
            authority: pending.authority(),
            generation: pending.generation(),
            thread_bound: PhantomData,
        })
    }

    /// Commits the mandatory provider outcome to authoritative engine state.
    pub fn finish(
        mut self,
        outcome: ExternalKeyDestructionOutcome<'authority>,
    ) -> SecurityOutcome<'authority, KeyLifecycleDecision> {
        let Some(pending) = self.pending.take() else {
            self.authority
                .fail_terminal(SecurityTerminal::ContractInvariant);
            return SecurityOutcome::Terminal(SecurityReceipt::new(
                self.authority,
                super::SecurityDecisionKind::KeyLifecycle,
            ));
        };
        let matches = match &outcome {
            ExternalKeyDestructionOutcome::Complete(proof) => {
                core::ptr::eq(proof.authority, pending.authority())
                    && proof.generation == pending.generation()
            }
            ExternalKeyDestructionOutcome::Failed {
                authority,
                generation,
                ..
            } => {
                core::ptr::eq(*authority, pending.authority())
                    && *generation == pending.generation()
            }
        };
        if !matches {
            return pending.resolve(SecurityResolution::Terminal(
                SecurityTerminal::ContractInvariant,
            ));
        }
        match outcome {
            ExternalKeyDestructionOutcome::Complete(_) => pending.resolve_verified_accepted(),
            ExternalKeyDestructionOutcome::Failed { .. } => pending.resolve(
                SecurityResolution::Terminal(SecurityTerminal::ExternalKeyDestruction),
            ),
        }
    }

    /// Abandons destruction and permanently fails the authority.
    pub fn abort(mut self) -> SecurityOutcome<'authority, KeyLifecycleDecision> {
        let Some(pending) = self.pending.take() else {
            self.authority
                .fail_terminal(SecurityTerminal::ContractInvariant);
            return SecurityOutcome::Terminal(SecurityReceipt::new(
                self.authority,
                super::SecurityDecisionKind::KeyLifecycle,
            ));
        };
        pending.resolve(SecurityResolution::Terminal(
            SecurityTerminal::ExternalKeyDestruction,
        ))
    }
}

impl Drop for ExternalKeyDestruction<'_> {
    fn drop(&mut self) {
        if let Some(pending) = self.pending.take() {
            let _ = pending.resolve(SecurityResolution::Terminal(
                SecurityTerminal::ExternalKeyDestruction,
            ));
        }
    }
}
