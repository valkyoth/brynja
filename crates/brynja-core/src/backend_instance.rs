//! Opaque backend-instance and feature-evidence identities.

use core::marker::PhantomData;

use crate::{BackendEvidenceOrigin, BackendProfile};

/// Opaque identity for one measured backend artifact and operational environment.
///
/// This value is authority-bearing metadata. It is neither copyable nor
/// formattable, exposes no measurement bytes, and has no public constructor.
/// A later reviewed platform or validated-module boundary must create it from
/// the exact artifact measurement and operational-environment identity.
///
/// Safe downstream code cannot manufacture an instance identity:
///
/// ```compile_fail
/// use brynja_core::BackendInstanceIdentity;
///
/// fn forge() -> BackendInstanceIdentity {
///     BackendInstanceIdentity {}
/// }
/// ```
pub struct BackendInstanceIdentity {
    artifact_measurement: [u8; 32],
    operational_environment: [u8; 32],
    thread_bound: PhantomData<*mut ()>,
}

impl BackendInstanceIdentity {
    pub(crate) const fn scalar() -> Self {
        Self {
            artifact_measurement: [0; 32],
            operational_environment: [0; 32],
            thread_bound: PhantomData,
        }
    }

    #[cfg(test)]
    pub(crate) const fn for_test(
        artifact_measurement: [u8; 32],
        operational_environment: [u8; 32],
    ) -> Self {
        Self {
            artifact_measurement,
            operational_environment,
            thread_bound: PhantomData,
        }
    }

    pub(crate) fn binding_matches(&self, other: &Self) -> bool {
        self.artifact_measurement == other.artifact_measurement
            && self.operational_environment == other.operational_environment
    }
}

/// Opaque proof that one exact backend instance's complete feature bundle was observed.
///
/// This type has no public constructor. A later reviewed compiler or platform
/// boundary must bind profile, measured instance, operational environment,
/// and evidence origin in one value.
///
/// ```compile_fail
/// use brynja_core::BackendFeatureEvidence;
///
/// fn forge() -> BackendFeatureEvidence {
///     BackendFeatureEvidence {}
/// }
/// ```
pub struct BackendFeatureEvidence {
    pub(crate) profile: BackendProfile,
    pub(crate) origin: BackendEvidenceOrigin,
    pub(crate) instance: BackendInstanceIdentity,
    thread_bound: PhantomData<*mut ()>,
}

impl BackendFeatureEvidence {
    #[cfg(test)]
    pub(crate) const fn for_test(
        profile: BackendProfile,
        origin: BackendEvidenceOrigin,
        instance: BackendInstanceIdentity,
    ) -> Self {
        Self {
            profile,
            origin,
            instance,
            thread_bound: PhantomData,
        }
    }
}
