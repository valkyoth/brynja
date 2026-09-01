//! Affine secret-lifetime and destruction contract.
//!
//! These types model initialization and mandatory destruction effects without
//! storing or exposing secret bytes. Brynja v0.10 deliberately provides no
//! production byte-backed secret constructor: that remains blocked until the
//! v0.11 complete-region zeroization primitive has emitted-code evidence.

use crate::{
    DestructionCause, DestructionComplete, DestructionFailure, DestructionOutcome,
    DestructionTargets, ProviderFailure, SecretDestructor,
    secret_destruction::{invariant_failure, invariant_failure_value},
};

/// A closed, value-free lifecycle-contract error.
///
/// The error contains no secret, length, offset, initialized-prefix value,
/// provider-native detail, or arbitrary text.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SecretContractError {
    /// A zero-byte region cannot represent a secret.
    EmptyRegion,
    /// No destruction target was selected.
    NoDestructionTarget,
}

/// Validated, secret-free policy for one abstract secret lifecycle.
///
/// This copyable value is configuration, not ownership. It contains only the
/// nonzero region size and the exact destruction-target set and deliberately
/// has no formatting implementation.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SecretLifecycleContract {
    region_bytes: usize,
    targets: DestructionTargets,
}

impl SecretLifecycleContract {
    /// Validates one lifecycle policy before any destructor is borrowed.
    pub const fn new(
        region_bytes: usize,
        targets: DestructionTargets,
    ) -> Result<Self, SecretContractError> {
        if region_bytes == 0 {
            Err(SecretContractError::EmptyRegion)
        } else if targets.is_empty() {
            Err(SecretContractError::NoDestructionTarget)
        } else {
            Ok(Self {
                region_bytes,
                targets,
            })
        }
    }
}

/// A write-only initialization contract.
///
/// This value stores only byte counts, target policy, and an exclusive borrow
/// of a destruction-effect implementation. It stores no secret bytes and has
/// no read operation. [`Self::acknowledge_write`] is a contract boundary that a
/// future byte-owning implementation may call only after it completely wrote
/// the acknowledged prefix. Calling it alone is not initialization evidence.
///
/// Dropping or explicitly aborting this value synchronously requests every
/// configured destruction duty. The type is affine and implements neither
/// cloning, copying, formatting, nor serialization.
#[must_use = "partial secret initialization must reach a terminal transition"]
pub struct SecretInitialization<'a, D: SecretDestructor> {
    expected: usize,
    initialized: usize,
    targets: DestructionTargets,
    destructor: Option<&'a mut D>,
}

/// Result of acknowledging one complete write.
#[must_use = "initialization transitions must be handled"]
pub enum InitializationTransition<'a, D: SecretDestructor> {
    /// More of the region remains write-only.
    Incomplete(SecretInitialization<'a, D>),
    /// The exact region is initialized and the abstract owner is readable.
    Readable(SecretState<'a, D>),
    /// The acknowledgement exceeded the region and destruction ran.
    Failed(DestructionOutcome),
}

/// An abstract readable-secret ownership contract.
///
/// `SecretState` contains no secret bytes and exposes no read method. Its
/// existence records that a future byte-owning boundary acknowledged complete
/// initialization. It cannot be cloned, copied, formatted, or serialized.
/// Explicit obsolescence, cancellation, provider failure, exhaustion,
/// replacement, and `Drop` all synchronously invoke the configured destruction
/// duties.
///
/// ```compile_fail
/// fn clone_owner<D: brynja_core::SecretDestructor>(
///     owner: brynja_core::SecretState<'_, D>,
/// ) {
///     let _copy = owner.clone();
/// }
/// ```
///
/// ```compile_fail
/// fn format_owner<D: brynja_core::SecretDestructor>(
///     owner: &brynja_core::SecretState<'_, D>,
/// ) {
///     let _args = format_args!("{owner:?}");
/// }
/// ```
#[must_use = "a readable-secret contract must be destroyed explicitly or by drop"]
pub struct SecretState<'a, D: SecretDestructor> {
    targets: DestructionTargets,
    destructor: Option<&'a mut D>,
}

/// Result of destroying an old secret before initializing its replacement.
#[must_use = "replacement must handle old-secret destruction before proceeding"]
pub enum ReplacementTransition<'a, D: SecretDestructor> {
    /// Old-secret destruction completed and the replacement is write-only.
    Initializing {
        /// Single-consumption completion token for the old secret.
        previous: DestructionComplete,
        /// Write-only initialization contract for the replacement.
        next: SecretInitialization<'a, D>,
    },
    /// The old secret was destroyed, but the replacement request was invalid.
    Rejected {
        /// Single-consumption completion token for the old secret.
        previous: DestructionComplete,
        /// Closed reason why replacement initialization was rejected.
        error: SecretContractError,
    },
    /// Old-secret destruction failed and the lifecycle is terminal.
    Failed(DestructionFailure),
}

impl<'a, D: SecretDestructor> SecretInitialization<'a, D> {
    /// Begins an abstract write-only lifecycle contract.
    ///
    /// This constructor does not accept, allocate, borrow, or initialize
    /// storage. It cannot create a production secret owner by itself.
    pub fn begin(contract: SecretLifecycleContract, destructor: &'a mut D) -> Self {
        Self {
            expected: contract.region_bytes,
            initialized: 0,
            targets: contract.targets,
            destructor: Some(destructor),
        }
    }

    /// Acknowledges a contiguous write that already completed successfully.
    ///
    /// Exact completion is the only route to [`SecretState`]. An overrun is a
    /// terminal initialization failure and immediately runs all destruction
    /// duties. A zero-byte acknowledgement remains incomplete.
    pub fn acknowledge_write(mut self, bytes: usize) -> InitializationTransition<'a, D> {
        let next = self.initialized.checked_add(bytes);
        match next {
            Some(value) if value < self.expected => {
                self.initialized = value;
                InitializationTransition::Incomplete(self)
            }
            Some(value) if value == self.expected => match self.destructor.take() {
                Some(destructor) => InitializationTransition::Readable(SecretState {
                    targets: self.targets,
                    destructor: Some(destructor),
                }),
                None => InitializationTransition::Failed(invariant_failure(
                    DestructionCause::InitializationFailure,
                )),
            },
            Some(_) | None => InitializationTransition::Failed(
                self.destroy(DestructionCause::InitializationFailure),
            ),
        }
    }

    /// Cancels initialization and immediately runs every destruction duty.
    pub fn cancel(self) -> DestructionOutcome {
        self.destroy(DestructionCause::Cancellation)
    }

    /// Terminates initialization after a provider failure.
    pub fn provider_failed(self, _failure: ProviderFailure) -> DestructionOutcome {
        self.destroy(DestructionCause::ProviderFailure)
    }

    /// Terminates initialization after bounded-resource exhaustion.
    pub fn exhausted(self) -> DestructionOutcome {
        self.destroy(DestructionCause::Exhaustion)
    }

    fn destroy(mut self, cause: DestructionCause) -> DestructionOutcome {
        match self.destructor.take() {
            Some(destructor) => {
                crate::secret_destruction::run_destruction(destructor, self.targets, cause)
            }
            None => invariant_failure(cause),
        }
    }
}

impl<D: SecretDestructor> Drop for SecretInitialization<'_, D> {
    fn drop(&mut self) {
        if let Some(destructor) = self.destructor.take()
            && let DestructionOutcome::Failed(failure) = crate::secret_destruction::run_destruction(
                destructor,
                self.targets,
                DestructionCause::InitializationFailure,
            )
        {
            destructor.handle_drop_failure(failure);
        }
    }
}

impl<'a, D: SecretDestructor> SecretState<'a, D> {
    /// Makes the secret obsolete and immediately runs every destruction duty.
    pub fn obsolete(self) -> DestructionOutcome {
        self.destroy(DestructionCause::Obsolete)
    }

    /// Cancels the owning operation and immediately destroys the secret.
    pub fn cancel(self) -> DestructionOutcome {
        self.destroy(DestructionCause::Cancellation)
    }

    /// Enters terminal cleanup after a provider failure.
    pub fn provider_failed(self, _failure: ProviderFailure) -> DestructionOutcome {
        self.destroy(DestructionCause::ProviderFailure)
    }

    /// Enters terminal cleanup after bounded-resource exhaustion.
    pub fn exhausted(self) -> DestructionOutcome {
        self.destroy(DestructionCause::Exhaustion)
    }

    /// Destroys the old secret before admitting replacement initialization.
    pub fn replace(mut self, region_bytes: usize) -> ReplacementTransition<'a, D> {
        let targets = self.targets;
        let destructor = match self.destructor.take() {
            Some(destructor) => destructor,
            None => {
                return ReplacementTransition::Failed(invariant_failure_value(
                    DestructionCause::Replacement,
                ));
            }
        };
        match crate::secret_destruction::run_destruction(
            destructor,
            targets,
            DestructionCause::Replacement,
        ) {
            DestructionOutcome::Failed(failure) => ReplacementTransition::Failed(failure),
            DestructionOutcome::Complete(previous) if region_bytes == 0 => {
                ReplacementTransition::Rejected {
                    previous,
                    error: SecretContractError::EmptyRegion,
                }
            }
            DestructionOutcome::Complete(previous) => ReplacementTransition::Initializing {
                previous,
                next: SecretInitialization {
                    expected: region_bytes,
                    initialized: 0,
                    targets,
                    destructor: Some(destructor),
                },
            },
        }
    }

    fn destroy(mut self, cause: DestructionCause) -> DestructionOutcome {
        match self.destructor.take() {
            Some(destructor) => {
                crate::secret_destruction::run_destruction(destructor, self.targets, cause)
            }
            None => invariant_failure(cause),
        }
    }
}

impl<D: SecretDestructor> Drop for SecretState<'_, D> {
    fn drop(&mut self) {
        if let Some(destructor) = self.destructor.take()
            && let DestructionOutcome::Failed(failure) = crate::secret_destruction::run_destruction(
                destructor,
                self.targets,
                DestructionCause::Drop,
            )
        {
            destructor.handle_drop_failure(failure);
        }
    }
}

#[cfg(test)]
mod assurance_contract;
