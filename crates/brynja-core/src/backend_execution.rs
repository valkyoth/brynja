//! CPU-context lease required immediately around accelerated kernel entry.

use core::marker::PhantomData;

use crate::{
    BackendDispatch, BackendDispatchError, BackendIdentity, BackendProfile,
    BackendRuntimeGeneration, BackendSession, ProviderOperation,
};

/// Opaque identity of one logical CPU or hart observation.
///
/// It is observational and has no public constructor. CPU numbers supplied by
/// application code are not accepted as execution evidence.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BackendCpuIdentity([u8; 32]);

impl BackendCpuIdentity {
    #[cfg(test)]
    pub(crate) const fn for_test(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Closed failure from immediate CPU-context revalidation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum BackendCpuRevalidationError {
    /// The current CPU or hart differs from the leased observation.
    CpuChanged,
    /// The exact complete usable feature predicate no longer holds.
    FeaturesUnavailable,
    /// Required operating-system or architectural state is unavailable.
    OperatingStateUnavailable,
    /// The platform migration or hot-plug generation changed.
    MigrationGenerationChanged,
}

/// Reviewed platform callback used while a CPU execution lease is held.
///
/// The later platform package must cover architectural dependencies such as
/// x86 OSXSAVE/XCR0 state and exact RISC-V extension dependencies in this
/// complete revalidation. This crate provides no implementation yet.
pub trait BackendCpuContext {
    /// Revalidates the exact observed CPU, migration generation, complete
    /// usable feature predicate, and required operating state.
    fn revalidate(
        &self,
        observed_cpu: BackendCpuIdentity,
        migration_generation: u64,
        profile: BackendProfile,
    ) -> Result<(), BackendCpuRevalidationError>;
}

/// Opaque platform-issued lease for one backend session and CPU observation.
///
/// The lease has no public constructor. A future reviewed platform boundary
/// must guarantee that its context either holds affinity/migration exclusion
/// through kernel entry or rechecks the full usable-feature predicate on every
/// entry. Merely remaining on one Rust thread is insufficient.
///
/// ```compile_fail
/// use brynja_core::{BackendCpuContext, BackendCpuLease, BackendSession};
///
/// fn forge<'a>(
///     context: &'a dyn BackendCpuContext,
///     session: &'a BackendSession,
/// ) -> BackendCpuLease<'a, 'a> {
///     BackendCpuLease { context, session }
/// }
/// ```
pub struct BackendCpuLease<'context, 'session> {
    context: &'context dyn BackendCpuContext,
    session: &'session BackendSession,
    observed_cpu: BackendCpuIdentity,
    migration_generation: u64,
    runtime: BackendRuntimeGeneration,
    thread_bound: PhantomData<*mut ()>,
}

impl<'context, 'session> BackendCpuLease<'context, 'session> {
    #[cfg(test)]
    pub(crate) const fn for_test(
        context: &'context dyn BackendCpuContext,
        session: &'session BackendSession,
        observed_cpu: BackendCpuIdentity,
        migration_generation: u64,
        runtime: BackendRuntimeGeneration,
    ) -> Self {
        Self {
            context,
            session,
            observed_cpu,
            migration_generation,
            runtime,
            thread_bound: PhantomData,
        }
    }

    pub(crate) fn revalidate(
        &self,
        session: &BackendSession,
        runtime: BackendRuntimeGeneration,
    ) -> Result<(), BackendDispatchError> {
        if !core::ptr::eq(self.session, session) || self.runtime != runtime {
            return Err(BackendDispatchError::CpuLeaseMismatch);
        }
        self.context
            .revalidate(
                self.observed_cpu,
                self.migration_generation,
                session.profile(),
            )
            .map_err(|error| match error {
                BackendCpuRevalidationError::CpuChanged => BackendDispatchError::CpuChanged,
                BackendCpuRevalidationError::FeaturesUnavailable => {
                    BackendDispatchError::CpuFeaturesUnavailable
                }
                BackendCpuRevalidationError::OperatingStateUnavailable => {
                    BackendDispatchError::CpuOperatingStateUnavailable
                }
                BackendCpuRevalidationError::MigrationGenerationChanged => {
                    BackendDispatchError::CpuMigrationGenerationChanged
                }
            })
    }
}

/// Opaque, non-escapable proof of immediate dispatch and CPU revalidation.
///
/// ```compile_fail
/// use brynja_core::{
///     BackendCpuLease, BackendDispatch, BackendKernelPermit, BackendRuntimeGeneration,
/// };
///
/// fn escape<'a>(
///     dispatch: &'a BackendDispatch<'a>,
///     lease: &'a BackendCpuLease<'a, 'a>,
/// ) -> BackendKernelPermit<'a> {
///     dispatch
///         .enter_kernel(BackendRuntimeGeneration::initial(), lease, |permit| permit)
///         .unwrap()
/// }
/// ```
pub struct BackendKernelPermit<'entry> {
    dispatch: &'entry BackendDispatch<'entry>,
    lease: &'entry BackendCpuLease<'entry, 'entry>,
}

impl BackendKernelPermit<'_> {
    /// Returns the exact operation authorized for this immediate entry.
    #[must_use]
    pub const fn operation(&self) -> ProviderOperation {
        self.dispatch.operation()
    }

    /// Returns the exact accelerated backend identity.
    #[must_use]
    pub fn identity(&self) -> BackendIdentity {
        self.lease.session.profile().identity()
    }
}

impl BackendDispatch<'_> {
    /// Revalidates authority and the current CPU context immediately around an
    /// accelerated kernel closure. No executable backend or public lease
    /// constructor exists yet.
    pub fn enter_kernel<R, F>(
        &self,
        runtime: BackendRuntimeGeneration,
        lease: &BackendCpuLease<'_, '_>,
        kernel: F,
    ) -> Result<R, BackendDispatchError>
    where
        F: for<'entry> FnOnce(BackendKernelPermit<'entry>) -> R,
    {
        if !matches!(
            self.session.profile().identity().class(),
            crate::BackendClass::Accelerated
        ) {
            return Err(BackendDispatchError::BackendClassMismatch);
        }
        self.validate(runtime)?;
        lease.revalidate(self.session, runtime)?;
        Ok(kernel(BackendKernelPermit {
            dispatch: self,
            lease,
        }))
    }
}
