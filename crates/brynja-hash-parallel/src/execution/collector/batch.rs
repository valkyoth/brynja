use super::{Collector, Operation};
use crate::execution::{
    Error as RootError, WorkerPolicy,
    batch::{self, Error, Leaves, Report},
};

impl<'plan, 'input, 'authority> Collector<'plan, 'input, 'authority> {
    /// Consumes exactly the next contiguous plan-bound group. Foreign, duplicate,
    /// missing, reordered or wrong-policy leaves cancel this root and clear CVs.
    /// Streaming roots cannot accept these scheduled completion tokens.
    pub fn merge_batch(&mut self, leaves: Leaves<'plan, 'input, '_>) -> Result<(), Error> {
        let mut guard = Operation {
            root: self,
            complete: false,
        };
        let root = &mut guard.root;
        let plan = root.binding.scheduled()?;
        let end = leaves
            .start
            .checked_add(leaves.count as u128)
            .ok_or(RootError::State)?;
        if root.phase != [1]
            || !core::ptr::eq(plan, leaves.plan)
            || leaves.start != root.merged_leaves()
            || leaves.count == 0
            || leaves.count > batch::CAPACITY
            || end > plan.leaf_count()
        {
            return Err(RootError::State.into());
        }
        let algorithm = if plan.identity.wide() {
            brynja_hash_sha3::hardened_batch::Algorithm::Shake256
        } else {
            brynja_hash_sha3::hardened_batch::Algorithm::Shake128
        };
        for index in 0..leaves.count {
            let accelerated = leaves.report.accelerated_slots & (1 << index) != 0;
            let accepted = match plan.workers {
                WorkerPolicy::Mixed => true,
                WorkerPolicy::Portable => !accelerated,
                WorkerPolicy::RequireAcceleration => accelerated,
            };
            if !accepted
                || leaves.inner.algorithm(index) != Some(algorithm)
                || leaves.inner.output_bits(index)
                    != Some(
                        plan.identity
                            .leaf_bytes()
                            .checked_mul(8)
                            .ok_or(RootError::State)?,
                    )
                || leaves.inner.expose(index).map(<[u8]>::len) != Some(plan.identity.leaf_bytes())
            {
                return Err(RootError::State.into());
            }
        }
        for index in 0..leaves.count {
            let merged = root
                .merged_leaves()
                .checked_add(1)
                .ok_or(RootError::State)?;
            let accelerated = root
                .accelerated_leaves()
                .checked_add(u128::from(
                    leaves.report.accelerated_slots & (1 << index) != 0,
                ))
                .ok_or(RootError::State)?;
            root.state
                .update(leaves.inner.expose(index).ok_or(RootError::State)?)?;
            root.merged = merged.to_le_bytes();
            root.accelerated = accelerated.to_le_bytes();
        }
        guard.complete = true;
        Ok(())
    }

    /// Executes the remaining scheduled leaves in groups of at most four.
    /// Controls bound leaf permutations; the plan bounds leaf count. Root work
    /// remains under its existing construction/output contract. Any failure or
    /// unwind cancels this root, even if earlier groups had already been merged.
    /// Require mode is per group; use Prefer explicitly for incomplete tails.
    pub fn execute_batched(
        &mut self,
        executor: &batch::Executor<'_>,
        workspace: &mut batch::Workspace,
        control: &mut batch::Control<'_>,
    ) -> Result<Report, Error> {
        workspace.clear();
        let mut guard = Operation {
            root: self,
            complete: false,
        };
        if guard.root.phase != [1] {
            return Err(RootError::State.into());
        }
        let plan = guard.root.binding.scheduled()?;
        let mut report = Report::default();
        while guard.root.merged_leaves() < plan.leaf_count() {
            let start = guard.root.merged_leaves();
            let remaining = plan
                .leaf_count()
                .checked_sub(start)
                .ok_or(RootError::State)?;
            let count = usize::try_from(remaining.min(batch::CAPACITY as u128))
                .map_err(|_| RootError::State)?;
            let leaves = plan
                .batch(start, count)?
                .execute(executor, workspace, control)?;
            let work = leaves.report();
            let accelerated = u128::from(work.accelerated_slots.count_ones());
            report.leaves = report
                .leaves
                .checked_add(count as u128)
                .ok_or(RootError::State)?;
            report.accelerated_leaves = report
                .accelerated_leaves
                .checked_add(accelerated)
                .ok_or(RootError::State)?;
            report.scalar_leaves = report
                .scalar_leaves
                .checked_add(
                    (count as u128)
                        .checked_sub(accelerated)
                        .ok_or(RootError::State)?,
                )
                .ok_or(RootError::State)?;
            report.vector_calls = report
                .vector_calls
                .checked_add(work.vector_calls)
                .ok_or(RootError::State)?;
            report.vector_permutations = report
                .vector_permutations
                .checked_add(work.vector_permutations)
                .ok_or(RootError::State)?;
            report.scalar_permutations = report
                .scalar_permutations
                .checked_add(work.scalar_permutations)
                .ok_or(RootError::State)?;
            guard.root.merge_batch(leaves)?;
        }
        guard.complete = true;
        Ok(report)
    }
}
