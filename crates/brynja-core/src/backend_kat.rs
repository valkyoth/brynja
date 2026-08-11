//! Session- and instance-bound known-answer-test evidence.

use core::marker::PhantomData;

use crate::{
    BackendFault, BackendInstanceIdentity, BackendProfile, BackendRuntimeGeneration,
    BackendServiceApproval, BackendSession,
};

/// Opaque trusted-provider proof that one direct startup KAT passed.
///
/// Evidence borrows the exact session and its measured backend-instance
/// identity. Equal profiles and generation counters therefore cannot redirect
/// a pass to another backend instance.
///
/// ```compile_fail
/// use brynja_core::BackendKatPass;
///
/// fn forge() -> BackendKatPass<'static> {
///     BackendKatPass {}
/// }
/// ```
pub struct BackendKatPass<'session> {
    pub(crate) session: &'session BackendSession,
    pub(crate) instance: &'session BackendInstanceIdentity,
    pub(crate) profile: BackendProfile,
    pub(crate) runtime: BackendRuntimeGeneration,
    pub(crate) testing_generation: u64,
    pub(crate) approval: BackendServiceApproval,
    thread_bound: PhantomData<*mut ()>,
}

impl<'session> BackendKatPass<'session> {
    #[cfg(test)]
    pub(crate) fn for_test(
        session: &'session BackendSession,
        profile: BackendProfile,
        runtime: BackendRuntimeGeneration,
        testing_generation: u64,
        approval: BackendServiceApproval,
    ) -> Self {
        Self {
            session,
            instance: session.instance(),
            profile,
            runtime,
            testing_generation,
            approval,
            thread_bound: PhantomData,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_instance_for_test(
        session: &'session BackendSession,
        instance: &'session BackendInstanceIdentity,
        approval: BackendServiceApproval,
    ) -> Self {
        let snapshot = session.snapshot();
        Self {
            session,
            instance,
            profile: session.profile(),
            runtime: snapshot.runtime_generation(),
            testing_generation: snapshot.generation(),
            approval,
            thread_bound: PhantomData,
        }
    }
}

/// Opaque trusted-provider proof that one direct startup KAT failed.
///
/// A failure is bound to the same exact session and measured instance as a
/// pass, so it cannot quarantine or stand in for another backend.
pub struct BackendKatFailure<'session> {
    pub(crate) session: &'session BackendSession,
    pub(crate) instance: &'session BackendInstanceIdentity,
    pub(crate) profile: BackendProfile,
    pub(crate) runtime: BackendRuntimeGeneration,
    pub(crate) testing_generation: u64,
    pub(crate) fault: BackendFault,
    thread_bound: PhantomData<*mut ()>,
}

impl<'session> BackendKatFailure<'session> {
    #[cfg(test)]
    pub(crate) fn for_test(
        session: &'session BackendSession,
        profile: BackendProfile,
        runtime: BackendRuntimeGeneration,
        testing_generation: u64,
        fault: BackendFault,
    ) -> Self {
        Self {
            session,
            instance: session.instance(),
            profile,
            runtime,
            testing_generation,
            fault,
            thread_bound: PhantomData,
        }
    }
}
