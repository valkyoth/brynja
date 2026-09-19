use super::{CAPACITY, Error, KernelReport, Leaves, Plan, RootError};
use brynja_core::clear_owned_region;
use core::{cell::Cell, marker::PhantomData};

/// Completed, plan-bound CVs that may move to the collector's thread.
/// No authority, unfinished hash state or workspace crosses that boundary.
/// Construction requires consuming completed Leaves; there is no byte importer.
/// Drop clears all 256 borrowed bytes, including inactive slots and short-CV tails.
/// Count, route and provenance fields are public metadata, not secret buffers.
///
/// ```
/// use brynja_hash_parallel::execution::batch::TransferredLeaves;
/// fn require<T: Send>() {} require::<TransferredLeaves<'_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::TransferredLeaves;
/// fn require<T: Sync>() {} require::<TransferredLeaves<'_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::TransferredLeaves;
/// fn require<T: Copy>() {} require::<TransferredLeaves<'_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::TransferredLeaves;
/// fn require<T: Clone>() {} require::<TransferredLeaves<'_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::TransferredLeaves;
/// fn require<T: core::fmt::Debug>() {} require::<TransferredLeaves<'_, '_, '_>>();
/// ```
/// ```compile_fail
/// use brynja_hash_parallel::execution::batch::TransferredLeaves;
/// fn import(bytes: &mut [[u8; 64]; 4]) -> TransferredLeaves<'static, 'static, '_> {
///     bytes.into()
/// }
/// ```
#[must_use = "merge or drop transported values so all borrowed storage clears"]
pub struct TransferredLeaves<'plan, 'input, 'out> {
    pub(in crate::execution) plan: &'plan Plan<'input>,
    pub(in crate::execution) start: u128,
    pub(in crate::execution) count: usize,
    pub(in crate::execution) report: KernelReport,
    pub(in crate::execution) values: &'out mut [[u8; 64]; CAPACITY],
    exclusive: PhantomData<Cell<()>>,
}
impl TransferredLeaves<'_, '_, '_> {
    /// Actual completed worker work; this is not live authority.
    #[must_use]
    pub const fn report(&self) -> KernelReport {
        self.report
    }
    /// Number of valid contiguous leaf values.
    #[must_use]
    pub const fn len(&self) -> usize {
        self.count
    }
    /// Completed groups are nonempty.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }
}
impl Drop for TransferredLeaves<'_, '_, '_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.values.as_flattened_mut());
    }
}
impl<'plan, 'input> Leaves<'plan, 'input, '_> {
    /// Consumes completed results into a separate clearing transport loan.
    /// Original CVs clear before return. All destination bytes clear on failure;
    /// success keeps them secret-owned until consumed by the exact collector.
    pub fn transfer<'out>(
        self,
        values: &'out mut [[u8; 64]; CAPACITY],
    ) -> Result<TransferredLeaves<'plan, 'input, 'out>, Error> {
        let _ = clear_owned_region(values.as_flattened_mut());
        let result = TransferredLeaves {
            plan: self.plan,
            start: self.start,
            count: self.count,
            report: self.report,
            values,
            exclusive: PhantomData,
        };
        let width = self.plan.identity().leaf_bytes();
        for index in 0..self.count {
            let source = self.inner.expose(index).ok_or(RootError::State)?;
            let destination = result
                .values
                .get_mut(index)
                .and_then(|v| v.get_mut(..width))
                .ok_or(RootError::State)?;
            if source.len() != destination.len() {
                return Err(RootError::State.into());
            }
            brynja_core::copy_secret_region(destination, source).map_err(|_| RootError::State)?;
        }
        Ok(result)
    }
}
#[cfg(test)]
mod tests;
