//! Version-neutral CPU-backend identity, feature, and policy values.

use core::marker::PhantomData;

use crate::{BackendFeatureEvidence, BackendInstanceIdentity, ProviderCapabilities};

/// One CPU-backend execution class.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendClass {
    /// Portable first-party scalar Rust.
    Scalar,
    /// A first-party ISA-specific accelerated implementation.
    Accelerated,
    /// A separately controlled validated-module implementation.
    ValidatedModule,
}

/// Caller-selected backend-selection policy.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendPolicy {
    /// Execute only the portable scalar backend.
    ScalarOnly,
    /// Prefer one admitted accelerator and report explicit scalar fallback.
    Opportunistic,
    /// Fail closed unless one admitted accelerator is available.
    RequiredAccelerated,
    /// Fail closed unless an approved validated module is available.
    ValidatedModuleOnly,
}

/// One sealed first-party backend identity.
///
/// Identity names a planned implementation boundary, not implementation,
/// availability, health, benchmark evidence, or FIPS validation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendIdentity {
    /// Portable scalar Rust.
    Scalar,
    /// x86 SHA extension backend.
    X86Sha,
    /// x86 AES plus carry-less multiplication backend.
    X86AesGcm,
    /// x86 AVX2 parallel backend.
    X86Avx2,
    /// x86 AVX-512 parallel backend.
    X86Avx512,
    /// AArch64 NEON plus SHA-2 backend.
    Aarch64Sha2,
    /// AArch64 NEON plus AES and polynomial multiplication backend.
    Aarch64AesGcm,
    /// RISC-V vector backend.
    RiscVVector,
    /// RISC-V scalar cryptography backend.
    RiscVScalarCrypto,
    /// Separately versioned validated-module backend.
    ValidatedModule,
}

impl BackendIdentity {
    /// Returns the execution class fixed by this identity.
    #[must_use]
    pub const fn class(self) -> BackendClass {
        match self {
            Self::Scalar => BackendClass::Scalar,
            Self::ValidatedModule => BackendClass::ValidatedModule,
            Self::X86Sha
            | Self::X86AesGcm
            | Self::X86Avx2
            | Self::X86Avx512
            | Self::Aarch64Sha2
            | Self::Aarch64AesGcm
            | Self::RiscVVector
            | Self::RiscVScalarCrypto => BackendClass::Accelerated,
        }
    }

    /// Returns the exact ISA feature bundle required by this identity.
    #[must_use]
    pub const fn required_features(self) -> BackendFeatures {
        let bits = match self {
            Self::Scalar | Self::ValidatedModule => 0,
            Self::X86Sha => BackendFeature::X86Sha.mask(),
            Self::X86AesGcm => BackendFeature::X86Aes.mask() | BackendFeature::X86Pclmulqdq.mask(),
            Self::X86Avx2 => BackendFeature::X86Avx2.mask(),
            Self::X86Avx512 => BackendFeature::X86Avx512F.mask(),
            Self::Aarch64Sha2 => {
                BackendFeature::Aarch64Neon.mask() | BackendFeature::Aarch64Sha2.mask()
            }
            Self::Aarch64AesGcm => {
                BackendFeature::Aarch64Neon.mask()
                    | BackendFeature::Aarch64Aes.mask()
                    | BackendFeature::Aarch64Pmull.mask()
            }
            Self::RiscVVector => BackendFeature::RiscVVector.mask(),
            Self::RiscVScalarCrypto => BackendFeature::RiscVScalarCrypto.mask(),
        };
        BackendFeatures::from_bits(bits)
    }
}

/// One exact CPU or ABI feature used by a planned backend.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendFeature {
    /// x86 SHA extensions.
    X86Sha,
    /// x86 AES extensions.
    X86Aes,
    /// x86 carry-less multiplication.
    X86Pclmulqdq,
    /// x86 AVX2.
    X86Avx2,
    /// x86 AVX-512 foundation.
    X86Avx512F,
    /// AArch64 NEON/Advanced SIMD.
    Aarch64Neon,
    /// AArch64 SHA-2 extensions.
    Aarch64Sha2,
    /// AArch64 AES extensions.
    Aarch64Aes,
    /// AArch64 polynomial multiplication.
    Aarch64Pmull,
    /// RISC-V vector extension.
    RiscVVector,
    /// RISC-V scalar cryptography extensions.
    RiscVScalarCrypto,
}

impl BackendFeature {
    const fn mask(self) -> u16 {
        match self {
            Self::X86Sha => 1,
            Self::X86Aes => 2,
            Self::X86Pclmulqdq => 4,
            Self::X86Avx2 => 8,
            Self::X86Avx512F => 16,
            Self::Aarch64Neon => 32,
            Self::Aarch64Sha2 => 64,
            Self::Aarch64Aes => 128,
            Self::Aarch64Pmull => 256,
            Self::RiscVVector => 512,
            Self::RiscVScalarCrypto => 1_024,
        }
    }
}

/// A closed feature-bundle construction failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendFeatureError {
    /// The same feature was assigned twice.
    Duplicate(BackendFeature),
}

/// A named single-assignment CPU-feature builder.
#[must_use = "the CPU feature bundle must be frozen"]
pub struct BackendFeaturesBuilder {
    bits: u16,
}

impl BackendFeaturesBuilder {
    /// Adds one exact feature.
    pub const fn enable(mut self, feature: BackendFeature) -> Result<Self, BackendFeatureError> {
        let mask = feature.mask();
        if self.bits & mask != 0 {
            Err(BackendFeatureError::Duplicate(feature))
        } else {
            self.bits |= mask;
            Ok(self)
        }
    }

    /// Freezes the exact feature set. An empty set is valid for scalar code.
    #[must_use]
    pub const fn freeze(self) -> BackendFeatures {
        BackendFeatures::from_bits(self.bits)
    }
}

/// An exact observational CPU-feature bundle.
///
/// This value is freely constructible and therefore never authorizes an
/// instruction. Only an opaque admitted-backend token can do that.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BackendFeatures {
    bits: u16,
}

impl BackendFeatures {
    const fn from_bits(bits: u16) -> Self {
        Self { bits }
    }

    /// Starts an empty named feature builder.
    pub const fn builder() -> BackendFeaturesBuilder {
        BackendFeaturesBuilder { bits: 0 }
    }

    /// Returns an empty scalar feature set.
    #[must_use]
    pub const fn empty() -> Self {
        Self::from_bits(0)
    }

    /// Reports whether one exact feature is present.
    #[must_use]
    pub const fn contains(self, feature: BackendFeature) -> bool {
        self.bits & feature.mask() != 0
    }

    /// Returns the number of exact features.
    #[must_use]
    pub const fn count(self) -> u32 {
        self.bits.count_ones()
    }
}

/// A backend-profile construction failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendProfileError {
    /// The feature set differed from the identity's exact required bundle.
    FeatureBundleMismatch,
}

/// An inert backend description.
///
/// Profiles are safe to copy and report because they carry no evidence and
/// grant no dispatch authority.
#[derive(Clone, Copy, Eq, Hash, PartialEq)]
pub struct BackendProfile {
    identity: BackendIdentity,
    features: BackendFeatures,
    operations: ProviderCapabilities,
}

impl BackendProfile {
    /// Validates an identity, exact feature bundle, and operation set.
    pub const fn new(
        identity: BackendIdentity,
        features: BackendFeatures,
        operations: ProviderCapabilities,
    ) -> Result<Self, BackendProfileError> {
        if features.bits != identity.required_features().bits {
            Err(BackendProfileError::FeatureBundleMismatch)
        } else {
            Ok(Self {
                identity,
                features,
                operations,
            })
        }
    }

    /// Returns the sealed identity.
    #[must_use]
    pub const fn identity(self) -> BackendIdentity {
        self.identity
    }

    /// Returns the exact required feature bundle.
    #[must_use]
    pub const fn features(self) -> BackendFeatures {
        self.features
    }

    /// Returns the exact operation set.
    #[must_use]
    pub const fn operations(self) -> ProviderCapabilities {
        self.operations
    }
}

/// Origin of observational candidate evidence.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendEvidenceOrigin {
    /// The complete feature bundle was guaranteed by compiler configuration.
    CompilerProven,
    /// A separately reviewed platform boundary observed the feature bundle.
    PlatformObserved,
}

/// An inert detected backend candidate.
///
/// A candidate cannot activate itself. Accelerated and validated candidates
/// have no public constructor in this milestone.
///
/// A freely constructed observational profile is not evidence:
///
/// ```compile_fail
/// use brynja_core::{BackendCandidate, BackendProfile};
///
/// fn inject(profile: BackendProfile) -> BackendCandidate {
///     BackendCandidate::from_evidence(profile)
/// }
/// ```
pub struct BackendCandidate {
    profile: BackendProfile,
    origin: BackendEvidenceOrigin,
    instance: BackendInstanceIdentity,
    thread_bound: PhantomData<*mut ()>,
}

impl BackendCandidate {
    /// Creates the always-safe scalar candidate.
    pub const fn scalar(operations: ProviderCapabilities) -> Result<Self, BackendProfileError> {
        match BackendProfile::new(
            BackendIdentity::Scalar,
            BackendFeatures::empty(),
            operations,
        ) {
            Ok(profile) => Ok(Self {
                profile,
                origin: BackendEvidenceOrigin::CompilerProven,
                instance: BackendInstanceIdentity::scalar(),
                thread_bound: PhantomData,
            }),
            Err(error) => Err(error),
        }
    }

    /// Converts opaque reviewed evidence into an inert candidate.
    ///
    /// [`BackendFeatureEvidence`] has no public constructor. Merely building a
    /// [`BackendProfile`] cannot enter this routine.
    #[must_use]
    pub const fn from_evidence(evidence: BackendFeatureEvidence) -> Self {
        Self {
            profile: evidence.profile,
            origin: evidence.origin,
            instance: evidence.instance,
            thread_bound: PhantomData,
        }
    }

    /// Returns the inert validated profile.
    #[must_use]
    pub const fn profile(&self) -> BackendProfile {
        self.profile
    }

    /// Returns how the candidate feature observation was obtained.
    #[must_use]
    pub const fn evidence_origin(&self) -> BackendEvidenceOrigin {
        self.origin
    }

    pub(crate) const fn instance(&self) -> &BackendInstanceIdentity {
        &self.instance
    }
}

/// Runtime or process generation used to invalidate inherited health state.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct BackendRuntimeGeneration(u64);

impl BackendRuntimeGeneration {
    /// Returns the first runtime generation.
    #[must_use]
    pub const fn initial() -> Self {
        Self(1)
    }

    /// Advances after a fork, runtime clone, or equivalent reset boundary.
    pub const fn next(self) -> Result<Self, BackendGenerationError> {
        match self.0.checked_add(1) {
            Some(value) => Ok(Self(value)),
            None => Err(BackendGenerationError::Exhausted),
        }
    }

    /// Returns the public generation value.
    #[must_use]
    pub const fn value(self) -> u64 {
        self.0
    }
}

/// A closed backend-generation failure.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendGenerationError {
    /// The monotonic generation could not advance.
    Exhausted,
}
