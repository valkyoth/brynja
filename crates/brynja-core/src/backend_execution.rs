//! Migration-excluding CPU guard required across accelerated kernel execution.

use core::marker::PhantomData;

use crate::{
    BackendDispatch, BackendDispatchError, BackendIdentity, BackendProfile,
    BackendRuntimeGeneration, BackendSession, ProviderOperation,
};

pub(crate) mod sealed {
    pub trait CpuContext {}
    pub trait CpuGuard {}
    pub trait Kernel {}
}

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

/// Opaque identity of one trusted platform CPU-context implementation.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BackendCpuContextIdentity([u8; 32]);

impl BackendCpuContextIdentity {
    #[cfg(test)]
    pub(crate) const fn for_test(value: [u8; 32]) -> Self {
        Self(value)
    }
}

/// Closed failure while acquiring a migration-excluding CPU guard.
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

/// Sealed guard that excludes migration until it is dropped.
///
/// Only reviewed implementations inside `brynja-core` can implement this
/// marker. v0.13.1 deliberately supplies none.
pub trait BackendCpuGuard: sealed::CpuGuard {}

/// Reviewed platform boundary that acquires a migration-excluding CPU guard.
///
/// Guard acquisition must both exclude CPU or hart migration for the complete
/// guard lifetime and check the observed CPU, migration generation, complete
/// usable feature predicate, and required operating or architectural state.
/// The trait is sealed and has no implementation in v0.13.1.
///
/// Safe downstream code cannot install a callback:
///
/// ```compile_fail
/// use brynja_core::BackendCpuContext;
///
/// struct UntrustedContext;
/// impl BackendCpuContext for UntrustedContext {}
/// ```
pub trait BackendCpuContext: sealed::CpuContext {
    /// Migration-excluding guard held across the direct kernel call.
    type Guard<'execution>: BackendCpuGuard + 'execution
    where
        Self: 'execution;

    /// Returns this exact reviewed context implementation's opaque identity.
    fn identity(&self) -> BackendCpuContextIdentity;

    /// Acquires migration exclusion and revalidates the complete CPU context.
    fn acquire_guard(
        &self,
        observed_cpu: BackendCpuIdentity,
        migration_generation: u64,
        profile: BackendProfile,
    ) -> Result<Self::Guard<'_>, BackendCpuRevalidationError>;
}

/// Opaque platform-issued lease for one backend session and CPU observation.
///
/// The lease has no public constructor and is bound to one reviewed context
/// identity. A future v0.13.2 boundary must issue it only with an exact CPU and
/// runtime observation.
///
/// ```compile_fail
/// use brynja_core::{BackendCpuLease, BackendSession};
///
/// fn forge(session: &BackendSession) -> BackendCpuLease<'_> {
///     BackendCpuLease { session }
/// }
/// ```
pub struct BackendCpuLease<'session> {
    session: &'session BackendSession,
    context: BackendCpuContextIdentity,
    observed_cpu: BackendCpuIdentity,
    migration_generation: u64,
    runtime: BackendRuntimeGeneration,
    thread_bound: PhantomData<*mut ()>,
}

impl<'session> BackendCpuLease<'session> {
    #[cfg(test)]
    pub(crate) const fn for_test(
        session: &'session BackendSession,
        context: BackendCpuContextIdentity,
        observed_cpu: BackendCpuIdentity,
        migration_generation: u64,
        runtime: BackendRuntimeGeneration,
    ) -> Self {
        Self {
            session,
            context,
            observed_cpu,
            migration_generation,
            runtime,
            thread_bound: PhantomData,
        }
    }

    fn validate_binding(
        &self,
        session: &BackendSession,
        runtime: BackendRuntimeGeneration,
    ) -> Result<(), BackendDispatchError> {
        if !core::ptr::eq(self.session, session) || self.runtime != runtime {
            Err(BackendDispatchError::CpuLeaseMismatch)
        } else {
            Ok(())
        }
    }
}

/// Opaque proof held only during guarded direct kernel execution.
pub struct BackendKernelPermit<'entry> {
    dispatch: &'entry BackendDispatch<'entry>,
    _execution_guard: &'entry dyn BackendCpuGuard,
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
        self.dispatch.session.profile().identity()
    }
}

/// Sealed accelerated kernel invoked directly under a CPU guard.
///
/// An application cannot insert an arbitrary closure between validation and
/// instruction use. Only reviewed kernels inside `brynja-core` can implement
/// this trait, and v0.13.1 deliberately supplies none.
///
/// ```compile_fail
/// use brynja_core::BackendKernel;
///
/// struct UntrustedKernel;
/// impl BackendKernel for UntrustedKernel {}
/// ```
pub trait BackendKernel: sealed::Kernel {
    /// Result returned by the exact kernel implementation.
    type Output;

    /// Executes immediately while the migration-excluding guard is live.
    fn execute(&self, permit: &BackendKernelPermit<'_>) -> Self::Output;
}

impl BackendDispatch<'_> {
    /// Acquires migration exclusion, then revalidates logical authority after
    /// every platform callback and directly invokes one sealed kernel.
    pub fn execute_kernel<C, K>(
        &self,
        runtime: BackendRuntimeGeneration,
        lease: &BackendCpuLease<'_>,
        context: &C,
        kernel: &K,
    ) -> Result<K::Output, BackendDispatchError>
    where
        C: BackendCpuContext,
        K: BackendKernel,
    {
        if !matches!(
            self.session.profile().identity().class(),
            crate::BackendClass::Accelerated
        ) {
            return Err(BackendDispatchError::BackendClassMismatch);
        }
        lease.validate_binding(self.session, runtime)?;
        if context.identity() != lease.context {
            return Err(BackendDispatchError::CpuLeaseMismatch);
        }
        let guard = context
            .acquire_guard(
                lease.observed_cpu,
                lease.migration_generation,
                self.session.profile(),
            )
            .map_err(map_revalidation_error)?;
        if context.identity() != lease.context {
            return Err(BackendDispatchError::CpuLeaseMismatch);
        }
        self.validate(runtime)?;
        let permit = BackendKernelPermit {
            dispatch: self,
            _execution_guard: &guard,
        };
        Ok(kernel.execute(&permit))
    }
}

fn map_revalidation_error(error: BackendCpuRevalidationError) -> BackendDispatchError {
    match error {
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
    }
}
