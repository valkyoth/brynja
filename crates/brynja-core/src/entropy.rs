//! Affine raw-entropy inputs and closed entropy failure domains.
//!
//! Raw entropy is caller-provided secret input. It is not initialized secure
//! randomness, a DRBG, an operating-system source, or evidence of validation.
//!
//! ```compile_fail
//! let mut bytes = [7_u8; 32];
//! let request = brynja_core::RawEntropyRequest::new(
//!     brynja_core::SecurityStrength::Bits256,
//!     brynja_core::EntropyPurpose::Instantiation,
//!     bytes.len(),
//! ).unwrap();
//! let mut initialization =
//!     brynja_core::SecretRegionInitialization::begin(&mut bytes).unwrap();
//! initialization.write(&[7_u8; 32]).unwrap();
//! let entropy = request.bind(initialization.finish().unwrap()).unwrap();
//! let _copy = entropy.clone();
//! ```

use crate::OwnedSecretRegion;

/// Maximum byte count accepted by one entropy or random request.
pub const MAX_RANDOM_REQUEST_BYTES: usize = 65_536;

/// One explicitly requested security strength.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum SecurityStrength {
    /// 128-bit security strength.
    Bits128,
    /// 192-bit security strength.
    Bits192,
    /// 256-bit security strength.
    Bits256,
}

impl SecurityStrength {
    /// Returns the named strength in bits.
    #[must_use]
    pub const fn bits(self) -> u16 {
        match self {
            Self::Bits128 => 128,
            Self::Bits192 => 192,
            Self::Bits256 => 256,
        }
    }

    /// Returns the minimum byte capacity capable of carrying this many bits.
    ///
    /// This is a storage bound, not an entropy estimate or validation claim.
    #[must_use]
    pub const fn minimum_bytes(self) -> usize {
        match self {
            Self::Bits128 => 16,
            Self::Bits192 => 24,
            Self::Bits256 => 32,
        }
    }
}

/// Why raw entropy is requested.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum EntropyPurpose {
    /// Initialize one secure-random engine state.
    Instantiation,
    /// Refresh an already initialized secure-random engine state.
    Reseed,
}

/// One exact raw-entropy request.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct RawEntropyRequest {
    strength: SecurityStrength,
    purpose: EntropyPurpose,
    bytes: usize,
}

impl RawEntropyRequest {
    /// Creates a bounded request for caller-provided raw entropy.
    pub const fn new(
        strength: SecurityStrength,
        purpose: EntropyPurpose,
        bytes: usize,
    ) -> Result<Self, EntropyContractError> {
        if bytes == 0 {
            return Err(EntropyContractError::EmptyInput);
        }
        if bytes > MAX_RANDOM_REQUEST_BYTES {
            return Err(EntropyContractError::RequestTooLarge);
        }
        if bytes < strength.minimum_bytes() {
            return Err(EntropyContractError::InsufficientInputCapacity);
        }
        Ok(Self {
            strength,
            purpose,
            bytes,
        })
    }

    /// Returns the requested security strength.
    #[must_use]
    pub const fn strength(self) -> SecurityStrength {
        self.strength
    }

    /// Returns the exact purpose of the input.
    #[must_use]
    pub const fn purpose(self) -> EntropyPurpose {
        self.purpose
    }

    /// Returns the exact required byte count.
    #[must_use]
    pub const fn bytes(self) -> usize {
        self.bytes
    }

    /// Binds exact-size affine secret memory to this request.
    ///
    /// The caller or source asserts that the bytes satisfy the declared
    /// strength. This operation checks storage and purpose metadata only.
    pub fn bind<'entropy>(
        self,
        input: OwnedSecretRegion<'entropy>,
    ) -> Result<RawEntropy<'entropy>, EntropyContractError> {
        if input.expose().len() != self.bytes {
            return Err(EntropyContractError::LengthMismatch);
        }
        Ok(RawEntropy {
            request: self,
            input,
        })
    }
}

/// Affine caller-provided raw entropy bound to one exact request.
///
/// This value cannot be cloned, copied, formatted, or serialized. Dropping it
/// clears the complete borrowed input through [`OwnedSecretRegion`].
pub struct RawEntropy<'entropy> {
    request: RawEntropyRequest,
    input: OwnedSecretRegion<'entropy>,
}

#[cfg(test)]
mod assurance_contract;

impl RawEntropy<'_> {
    /// Returns the exact request metadata.
    #[must_use]
    pub const fn request(&self) -> RawEntropyRequest {
        self.request
    }

    /// Borrows the raw secret bytes for an implementing engine.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        self.input.expose()
    }
}

/// A closed raw-entropy or secure-random contract failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum EntropyContractError {
    /// A secret input or output region was empty.
    EmptyInput,
    /// A request exceeded the fixed per-request byte ceiling.
    RequestTooLarge,
    /// The byte capacity cannot carry the declared security-strength bits.
    InsufficientInputCapacity,
    /// Supplied storage did not have the exact requested length.
    LengthMismatch,
    /// Entropy was supplied for the wrong state transition.
    PurposeMismatch,
    /// Entropy or an engine did not meet the configured security strength.
    StrengthMismatch,
    /// The configured reseed interval was zero or above its fixed ceiling.
    InvalidReseedInterval,
}

/// Whether an engine-reported fault permits another attempt.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum EntropyFailureKind {
    /// The exact operation may be attempted again without using its output.
    Retryable,
    /// The engine cannot safely produce further output.
    Permanent,
}

/// The engine transition that failed.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum EntropyFailureStage {
    /// Initial engine-state construction.
    Instantiate,
    /// Secure-random byte generation.
    Generate,
    /// Engine-state reseeding.
    Reseed,
    /// Secret-state destruction.
    Uninstantiate,
}

/// A secret-free engine failure classification.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct EntropyFailure {
    kind: EntropyFailureKind,
    stage: EntropyFailureStage,
}

impl EntropyFailure {
    /// Constructs a closed engine failure without provider text or bytes.
    #[must_use]
    pub const fn new(kind: EntropyFailureKind, stage: EntropyFailureStage) -> Self {
        Self { kind, stage }
    }

    /// Returns whether this failure permits retry.
    #[must_use]
    pub const fn kind(self) -> EntropyFailureKind {
        self.kind
    }

    /// Returns the failed engine transition.
    #[must_use]
    pub const fn stage(self) -> EntropyFailureStage {
        self.stage
    }
}
