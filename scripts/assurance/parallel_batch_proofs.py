"""Harnesses appended only to isolated copies of the real ParallelHash modules.

Private-state injection intentionally includes impossible/corrupt counters. This
proves the local predicates, not that the injected state is cryptographically
valid or reachable through public APIs. No method under proof is replaced.
"""

BATCH = r'''
#[cfg(kani)]
mod batch_qualification {
    use super::*;
    #[kani::proof]
    fn exact_batch_range() {
        let mut plan = Plan::new(super::super::Identity::ParallelHash128, &[], 1, 1).unwrap();
        let leaves: u128 = kani::any();
        let start: u128 = kani::any();
        let count: usize = kani::any();
        plan.leaves = leaves;
        let result = plan.batch(start, count);
        // Independent subtraction formulation: no potentially overflowing sum.
        let valid = count >= 1 && count <= 4 && start <= leaves
            && (count as u128) <= leaves - start;
        assert_eq!(result.is_ok(), valid);
        if let Ok(job) = result {
            assert!(core::ptr::eq(job.plan, &plan));
            assert_eq!(job.start, start);
            assert_eq!(job.count, count);
        }
        assert_eq!(plan.leaf_count(), leaves);
    }
}
'''

BINDING = r'''
#[cfg(kani)]
mod batch_qualification {
    use super::*;
    #[kani::proof]
    fn distinct_completion_domains() {
        let limit: u128 = kani::any();
        let merged: u128 = kani::any();
        let proof: bool = kani::any();
        let mut plan = Plan::new(Identity::ParallelHash128, &[], 1, 1).unwrap();
        plan.leaves = limit;
        let scheduled = Binding::Scheduled(&plan);
        assert_eq!(scheduled.complete(merged, proof), merged == limit && !proof);
        assert!(core::ptr::eq(scheduled.scheduled().unwrap(), &plan));
        let streaming = Binding::Streaming {
            identity: Identity::ParallelHash128, block: 1,
            limit, workers: WorkerPolicy::Mixed,
        };
        assert_eq!(streaming.complete(merged, proof), proof && merged <= limit);
        assert!(streaming.scheduled().is_err());
    }
}
'''

# Construct a real, valid empty cSHAKE owner, without absorbing the ParallelHash
# domain or running a permutation. Only the completion predicate reads this root.
COLLECTOR_SETUP = r'''
#[cfg(kani)]
impl Collector<'static, 'static, 'static> {
    pub(in crate::execution) fn qualification_root(merged: u128) -> Self {
        Self {
            binding: Binding::Streaming {
                identity: super::Identity::ParallelHash128,
                block: 1, limit: u128::MAX, workers: super::WorkerPolicy::Mixed,
            },
            state: State::Portable128(brynja_hash_sha3::HardenedCshake128::new(&[], &[]).unwrap()),
            merged: merged.to_le_bytes(), accelerated: [0; 16],
            output_bits: [0; 16], phase: [1],
        }
    }
}
'''

STREAM = r'''
#[cfg(kani)]
mod batch_qualification {
    use super::*;
    // A bounded owner initialization is needed, not a hash/permutation proof.
    // Avoid Drop here: cleanup is a separate emitted-code/runtime obligation.
    fn check(total: u128, pending: u128, merged: u128, block: usize, expected: u128) {
        let executor = Executor::portable();
        let mut storage = [];
        let stream = core::mem::ManuallyDrop::new(Stream {
            root: Collector::qualification_root(merged), executor: &executor,
            workspace: &mut storage, hash: batch::Workspace::new(),
            used: pending.to_le_bytes(), input_bits: total.to_le_bytes(),
            block, limit: u128::MAX,
        });
        assert_eq!(stream.expected(total), Ok(expected));
        assert_eq!(stream.check_complete().is_ok(), pending == 0 && merged == expected);
        assert_eq!(stream.used, pending.to_le_bytes());
        assert_eq!(stream.input_bits(), total);
        assert_eq!(stream.root.merged_leaves(), merged);
    }
    #[kani::proof]
    #[kani::unwind(33)]
    fn full_width_stream_completion() {
        let total: u128 = kani::any();
        let pending: u128 = kani::any();
        let merged: u128 = kani::any();
        // B=1 spans the entire u128 bit-count domain, including MAX.
        let expected = (total >> 3) + u128::from(total & 7 != 0);
        check(total, pending, merged, 1, expected);
    }
    #[kani::proof]
    #[kani::unwind(33)]
    fn non_power_of_two_stream_completion() {
        let total: u16 = kani::any();
        let pending: u128 = kani::any();
        let merged: u128 = kani::any();
        // B=3: independent ceil formula has no overflow in the widened domain.
        let expected = (u32::from(total) + 23) / 24;
        check(u128::from(total), pending, merged, 3, u128::from(expected));
    }
}
'''

SOURCES = {
    'execution/batch.rs': BATCH,
    'execution/binding.rs': BINDING,
    'execution/collector.rs': COLLECTOR_SETUP,
    'execution/stream/batch.rs': STREAM,
}
HARNESSES = {
    'range': 'execution::batch::batch_qualification::exact_batch_range',
    'binding': 'execution::binding::batch_qualification::distinct_completion_domains',
    'completion': 'execution::stream::batch::batch_qualification::full_width_stream_completion',
    'rounding': 'execution::stream::batch::batch_qualification::non_power_of_two_stream_completion',
}
MUTANTS = (
    ('range', 'execution/batch.rs', 'start.checked_add(count as u128).ok_or(RootError::State)?',
     'start.wrapping_add(count as u128)'),
    ('range', 'execution/batch.rs', 'count == 0 || count > CAPACITY || end > self.leaf_count()',
     'count > CAPACITY || end > self.leaf_count()'),
    ('range', 'execution/batch.rs', 'count > CAPACITY', 'count > CAPACITY + 1'),
    ('binding', 'execution/binding.rs', '!streaming_complete && merged == plan.leaves',
     'merged == plan.leaves'),
    ('binding', 'execution/binding.rs', 'streaming_complete && merged <= *limit',
     'merged <= *limit'),
    ('binding', 'execution/binding.rs', 'merged == plan.leaves', 'merged <= plan.leaves'),
    ('completion', 'execution/stream/batch.rs', 'self.used()? != 0 || ', ''),
    ('completion', 'execution/stream/batch.rs',
     'self.root.merged_leaves() != self.expected(self.input_bits())?',
     'self.root.merged_leaves() > self.expected(self.input_bits())?'),
    ('rounding', 'execution/stream/batch.rs', 'full.checked_add(u128::from(partial))',
     'full.checked_add(0)'),
)
