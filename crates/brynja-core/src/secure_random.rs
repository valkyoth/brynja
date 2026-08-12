//! Initialized secure-random state, request, fork, and reseed contracts.
//!
//! The wrapper is intentionally neither cloneable nor formattable:
//!
//! ```compile_fail
//! fn duplicate<E: brynja_core::SecureRandomEngine>(
//!     state: brynja_core::SecureRandom<E>,
//! ) {
//!     let _copy = state.clone();
//! }
//! ```

use crate::{
    EntropyContractError, EntropyFailure, EntropyFailureKind, EntropyFailureStage, EntropyPurpose,
    MAX_RANDOM_REQUEST_BYTES, OwnedSecretRegion, RawEntropy, SecretMemoryError,
    SecretRegionInitialization, SecurityStrength,
};

/// Maximum successful generate calls permitted between reseeds.
pub const MAX_RESEED_INTERVAL: u64 = 1_u64 << 48;

/// Why initialized secure randomness is requested.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RandomPurpose {
    /// Generate long-term or ephemeral key material.
    KeyGeneration,
    /// Generate a nonce whose uniqueness depends on secure randomness.
    Nonce,
    /// Generate protocol-visible random fields.
    ProtocolRandom,
    /// Generate secret blinding material.
    Blinding,
    /// Generate secret padding material.
    Padding,
}

/// One bounded initialized-secure-random request.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SecureRandomRequest {
    strength: SecurityStrength,
    purpose: RandomPurpose,
    bytes: usize,
}

impl SecureRandomRequest {
    /// Creates one exact nonempty bounded request.
    pub const fn new(
        strength: SecurityStrength,
        purpose: RandomPurpose,
        bytes: usize,
    ) -> Result<Self, EntropyContractError> {
        if bytes == 0 {
            return Err(EntropyContractError::EmptyInput);
        }
        if bytes > MAX_RANDOM_REQUEST_BYTES {
            return Err(EntropyContractError::RequestTooLarge);
        }
        Ok(Self {
            strength,
            purpose,
            bytes,
        })
    }

    /// Returns the required security strength.
    #[must_use]
    pub const fn strength(self) -> SecurityStrength {
        self.strength
    }

    /// Returns the exact use of the output.
    #[must_use]
    pub const fn purpose(self) -> RandomPurpose {
        self.purpose
    }

    /// Returns the exact requested output size.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.bytes
    }
}

/// A monotonic process/runtime generation used to invalidate inherited state.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct RandomRuntimeGeneration(u64);

impl RandomRuntimeGeneration {
    /// Returns the first runtime generation.
    #[must_use]
    pub const fn initial() -> Self {
        Self(1)
    }

    /// Advances after fork, process cloning, snapshot restore, or equivalent.
    pub const fn next(self) -> Result<Self, SecureRandomError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(SecureRandomError::Permanent(EntropyFailureStage::Reseed)),
        }
    }

    /// Returns the public generation value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// Immutable initialization and reseed policy.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct SecureRandomConfig {
    strength: SecurityStrength,
    reseed_interval: u64,
}

impl SecureRandomConfig {
    /// Creates a configuration with an exact successful-request interval.
    pub const fn new(
        strength: SecurityStrength,
        reseed_interval: u64,
    ) -> Result<Self, EntropyContractError> {
        if reseed_interval == 0 || reseed_interval > MAX_RESEED_INTERVAL {
            return Err(EntropyContractError::InvalidReseedInterval);
        }
        Ok(Self {
            strength,
            reseed_interval,
        })
    }

    /// Returns the configured security strength.
    #[must_use]
    pub const fn strength(self) -> SecurityStrength {
        self.strength
    }

    /// Returns the successful-request ceiling before mandatory reseed.
    #[must_use]
    pub const fn reseed_interval(self) -> u64 {
        self.reseed_interval
    }
}

/// Result of an engine's complete secret-state destruction duty.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum RandomStateDestruction {
    /// Every engine-owned secret byte and external state was destroyed.
    Complete,
    /// Complete destruction could not be established.
    Failed,
}

/// Downstream implementation boundary for one secure-random mechanism.
///
/// Implementations must be first-party Rust in Brynja packages, or explicitly
/// caller-provided. Returning success or destruction completion is a security
/// assertion. This trait grants no FIPS status.
pub trait SecureRandomEngine {
    /// Returns the greatest security strength this exact engine can provide.
    fn maximum_strength(&self) -> SecurityStrength;

    /// Initializes secret state from exact-purpose raw entropy.
    fn instantiate(&mut self, entropy: &RawEntropy<'_>) -> Result<(), EntropyFailureKind>;

    /// Writes the complete request into write-only transactional storage.
    fn generate(
        &mut self,
        request: SecureRandomRequest,
        output: &mut SecretRegionInitialization<'_>,
    ) -> Result<(), EntropyFailureKind>;

    /// Refreshes secret state from exact-purpose raw entropy.
    fn reseed(&mut self, entropy: &RawEntropy<'_>) -> Result<(), EntropyFailureKind>;

    /// Destroys all engine-owned secret state synchronously.
    fn uninstantiate(&mut self) -> RandomStateDestruction;

    /// Handles a destruction failure reached through any teardown route.
    ///
    /// Returning asserts the failure was made durable or a fail-stop response
    /// was initiated, so silent continued use is impossible.
    fn handle_destruction_failure(&mut self);
}

/// A closed secure-random state-machine failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum SecureRandomError {
    /// Raw entropy metadata did not match the required transition.
    Contract(EntropyContractError),
    /// The caller must reseed before another generate operation.
    ReseedRequired,
    /// A changed runtime generation requires post-fork reseed.
    ForkReseedRequired,
    /// An older runtime generation indicates rollback or stale state.
    RuntimeRollback,
    /// A retryable engine fault occurred at the named transition.
    Retryable(EntropyFailureStage),
    /// The state is permanently unusable after the named transition.
    Permanent(EntropyFailureStage),
}

impl From<SecretMemoryError> for SecureRandomError {
    fn from(error: SecretMemoryError) -> Self {
        match error {
            SecretMemoryError::EmptyRegion => Self::Contract(EntropyContractError::EmptyInput),
            SecretMemoryError::LengthOverflow | SecretMemoryError::InsufficientCapacity => {
                Self::Contract(EntropyContractError::LengthMismatch)
            }
            SecretMemoryError::IncompleteInitialization => {
                Self::Permanent(EntropyFailureStage::Generate)
            }
        }
    }
}

/// Non-cloneable initialized secure-random state around one exact engine.
///
/// The wrapper latches permanent failures, limits successful requests between
/// reseeds, and requires the caller to present the current runtime generation
/// on every stateful operation.
pub struct SecureRandom<E: SecureRandomEngine> {
    engine: Option<E>,
    config: SecureRandomConfig,
    runtime: RandomRuntimeGeneration,
    requests_since_reseed: u64,
    fork_reseed_required: bool,
    permanent_failure: Option<EntropyFailureStage>,
}

impl<E: SecureRandomEngine> SecureRandom<E> {
    /// Initializes one engine from exact-purpose caller-provided raw entropy.
    pub fn instantiate(
        mut engine: E,
        config: SecureRandomConfig,
        runtime: RandomRuntimeGeneration,
        entropy: RawEntropy<'_>,
    ) -> Result<Self, SecureRandomError> {
        if let Err(error) =
            validate_entropy(&entropy, EntropyPurpose::Instantiation, config.strength())
        {
            destroy_failed_engine(&mut engine);
            return Err(error);
        }
        if engine.maximum_strength() < config.strength() {
            destroy_failed_engine(&mut engine);
            return Err(SecureRandomError::Contract(
                EntropyContractError::StrengthMismatch,
            ));
        }
        if let Err(kind) = engine.instantiate(&entropy) {
            destroy_failed_engine(&mut engine);
            return Err(classify(kind, EntropyFailureStage::Instantiate));
        }
        Ok(Self {
            engine: Some(engine),
            config,
            runtime,
            requests_since_reseed: 0,
            fork_reseed_required: false,
            permanent_failure: None,
        })
    }

    /// Returns the immutable configured policy.
    #[must_use]
    pub const fn config(&self) -> SecureRandomConfig {
        self.config
    }

    /// Returns the runtime generation bound to current secret state.
    #[must_use]
    pub const fn runtime_generation(&self) -> RandomRuntimeGeneration {
        self.runtime
    }

    /// Returns successful generate calls since the last seed transition.
    #[must_use]
    pub const fn requests_since_reseed(&self) -> u64 {
        self.requests_since_reseed
    }

    /// Invalidates inherited state after fork or equivalent runtime cloning.
    pub fn mark_fork(&mut self, next: RandomRuntimeGeneration) -> Result<(), SecureRandomError> {
        self.ensure_usable()?;
        if next <= self.runtime {
            self.latch_permanent(EntropyFailureStage::Reseed);
            return Err(SecureRandomError::RuntimeRollback);
        }
        self.runtime = next;
        self.fork_reseed_required = true;
        Ok(())
    }

    /// Reseeds the exact engine and resets request accounting transactionally.
    pub fn reseed(
        &mut self,
        runtime: RandomRuntimeGeneration,
        entropy: RawEntropy<'_>,
    ) -> Result<(), SecureRandomError> {
        self.ensure_runtime(runtime)?;
        validate_entropy(&entropy, EntropyPurpose::Reseed, self.config.strength())?;
        let result = match self.engine.as_mut() {
            Some(engine) => engine.reseed(&entropy),
            None => return Err(self.permanent_error(EntropyFailureStage::Reseed)),
        };
        match result {
            Ok(()) => {
                self.requests_since_reseed = 0;
                self.fork_reseed_required = false;
                Ok(())
            }
            Err(EntropyFailureKind::Retryable) => {
                Err(SecureRandomError::Retryable(EntropyFailureStage::Reseed))
            }
            Err(EntropyFailureKind::Permanent) => {
                self.latch_permanent(EntropyFailureStage::Reseed);
                Err(SecureRandomError::Permanent(EntropyFailureStage::Reseed))
            }
        }
    }

    /// Generates exact-length secret output into one caller-owned region.
    ///
    /// The region is cleared before validation. Partial writes and every error
    /// clear the complete region before returning it to the caller.
    pub fn generate<'output>(
        &mut self,
        runtime: RandomRuntimeGeneration,
        request: SecureRandomRequest,
        output: &'output mut [u8],
    ) -> Result<OwnedSecretRegion<'output>, SecureRandomError> {
        let output_length = output.len();
        let mut initialization = SecretRegionInitialization::begin(output)?;
        self.ensure_runtime(runtime)?;
        if self.fork_reseed_required {
            return Err(SecureRandomError::ForkReseedRequired);
        }
        if request.strength() > self.config.strength() {
            return Err(SecureRandomError::Contract(
                EntropyContractError::StrengthMismatch,
            ));
        }
        if request.bytes() != output_length {
            return Err(SecureRandomError::Contract(
                EntropyContractError::LengthMismatch,
            ));
        }
        if self.requests_since_reseed >= self.config.reseed_interval() {
            return Err(SecureRandomError::ReseedRequired);
        }
        let result = match self.engine.as_mut() {
            Some(engine) => engine.generate(request, &mut initialization),
            None => return Err(self.permanent_error(EntropyFailureStage::Generate)),
        };
        match result {
            Ok(()) => {
                let output = match initialization.finish() {
                    Ok(output) => output,
                    Err(_) => {
                        self.latch_permanent(EntropyFailureStage::Generate);
                        return Err(SecureRandomError::Permanent(EntropyFailureStage::Generate));
                    }
                };
                let Some(next) = self.requests_since_reseed.checked_add(1) else {
                    self.latch_permanent(EntropyFailureStage::Generate);
                    return Err(SecureRandomError::Permanent(EntropyFailureStage::Generate));
                };
                self.requests_since_reseed = next;
                Ok(output)
            }
            Err(EntropyFailureKind::Retryable) => {
                Err(SecureRandomError::Retryable(EntropyFailureStage::Generate))
            }
            Err(EntropyFailureKind::Permanent) => {
                self.latch_permanent(EntropyFailureStage::Generate);
                Err(SecureRandomError::Permanent(EntropyFailureStage::Generate))
            }
        }
    }

    /// Explicitly destroys engine state and consumes the wrapper.
    pub fn uninstantiate(mut self) -> Result<(), EntropyFailure> {
        let Some(mut engine) = self.engine.take() else {
            return Err(EntropyFailure::new(
                EntropyFailureKind::Permanent,
                EntropyFailureStage::Uninstantiate,
            ));
        };
        match engine.uninstantiate() {
            RandomStateDestruction::Complete => Ok(()),
            RandomStateDestruction::Failed => {
                engine.handle_destruction_failure();
                Err(EntropyFailure::new(
                    EntropyFailureKind::Permanent,
                    EntropyFailureStage::Uninstantiate,
                ))
            }
        }
    }

    fn ensure_usable(&self) -> Result<(), SecureRandomError> {
        match self.permanent_failure {
            Some(stage) => Err(SecureRandomError::Permanent(stage)),
            None if self.engine.is_none() => Err(SecureRandomError::Permanent(
                EntropyFailureStage::Uninstantiate,
            )),
            None => Ok(()),
        }
    }

    fn ensure_runtime(
        &mut self,
        runtime: RandomRuntimeGeneration,
    ) -> Result<(), SecureRandomError> {
        self.ensure_usable()?;
        if runtime < self.runtime {
            self.latch_permanent(EntropyFailureStage::Reseed);
            Err(SecureRandomError::RuntimeRollback)
        } else if runtime > self.runtime {
            self.runtime = runtime;
            self.fork_reseed_required = true;
            Err(SecureRandomError::ForkReseedRequired)
        } else {
            Ok(())
        }
    }

    fn permanent_error(&self, fallback: EntropyFailureStage) -> SecureRandomError {
        SecureRandomError::Permanent(self.permanent_failure.unwrap_or(fallback))
    }

    fn latch_permanent(&mut self, stage: EntropyFailureStage) {
        if self.permanent_failure.is_none() {
            self.permanent_failure = Some(stage);
        }
        if let Some(mut engine) = self.engine.take()
            && matches!(engine.uninstantiate(), RandomStateDestruction::Failed)
        {
            engine.handle_destruction_failure();
        }
    }
}

impl<E: SecureRandomEngine> Drop for SecureRandom<E> {
    fn drop(&mut self) {
        if let Some(engine) = self.engine.as_mut()
            && matches!(engine.uninstantiate(), RandomStateDestruction::Failed)
        {
            engine.handle_destruction_failure();
        }
    }
}

fn validate_entropy(
    entropy: &RawEntropy<'_>,
    purpose: EntropyPurpose,
    strength: SecurityStrength,
) -> Result<(), SecureRandomError> {
    if entropy.request().purpose() != purpose {
        return Err(SecureRandomError::Contract(
            EntropyContractError::PurposeMismatch,
        ));
    }
    if entropy.request().strength() < strength {
        return Err(SecureRandomError::Contract(
            EntropyContractError::StrengthMismatch,
        ));
    }
    Ok(())
}

const fn classify(kind: EntropyFailureKind, stage: EntropyFailureStage) -> SecureRandomError {
    match kind {
        EntropyFailureKind::Retryable => SecureRandomError::Retryable(stage),
        EntropyFailureKind::Permanent => SecureRandomError::Permanent(stage),
    }
}

fn destroy_failed_engine<E: SecureRandomEngine>(engine: &mut E) {
    if matches!(engine.uninstantiate(), RandomStateDestruction::Failed) {
        engine.handle_destruction_failure();
    }
}
