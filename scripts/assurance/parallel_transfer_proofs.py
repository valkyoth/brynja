"""Real collector/transport proofs with injected completed tokens, not hash proofs.

Private setup supplies a completed token and a modeled sponge result. Production
merge, policy checks, accounting, guard cancellation and transport Drop execute
unchanged. Sponge absorption and the volatile primitive's byte effect are modeled;
this is not cryptographic or machine-store qualification.
"""

TRANSFER_SETUP = r'''
#[cfg(kani)]
impl<'plan, 'input, 'out> TransferredLeaves<'plan, 'input, 'out> {
    pub(in crate::execution) fn qualification_token(
        plan: &'plan Plan<'input>, start: u128, count: usize,
        mask: u8, values: &'out mut [[u8; 64]; CAPACITY],
    ) -> Self {
        Self {
            plan, start, count, values,
            report: KernelReport { accelerated_slots: mask, ..KernelReport::default() },
            exclusive: PhantomData,
        }
    }
}
'''

MERGE = r'''
#[cfg(kani)]
mod transfer_qualification {
    use super::*;
    use crate::execution::{Identity, Plan, binding::Binding, backend::State};
    // Volatile machine stores are separately inspected in compiler evidence.
    // Model their byte effect here, retaining every actual owner cleanup call.
    fn clear(bytes: &mut [u8]) { bytes.fill(0); }
    // Model a backend returning success or failure, without expanding Keccak.
    // The enum variant encodes only this test choice, not a real algorithm route.
    fn absorb<'a: 'a>(state: &mut State<'a>, _input: &[u8]) -> Result<(), RootError> {
        if matches!(state, State::Portable128(_)) { Ok(()) } else { Err(RootError::State) }
    }
    fn check(wide: bool) {
        let total: u128 = kani::any();
        let position: u128 = kani::any();
        let start: u128 = kani::any();
        let accelerated: u128 = kani::any();
        let count: usize = kani::any();
        let backend_failure: bool = kani::any();
        let mask: u8 = kani::any();
        let active = (1_u8 << count.min(4)) - 1;
        kani::assume(mask & !active == 0); // valid completed-report provenance
        let foreign: bool = kani::any();
        let streaming: bool = kani::any();
        let phase: u8 = kani::any();
        let policy: u8 = kani::any();
        kani::assume(policy < 3);
        let workers = match policy {
            0 => WorkerPolicy::Mixed,
            1 => WorkerPolicy::Portable,
            _ => WorkerPolicy::RequireAcceleration,
        };
        let identity = if wide { Identity::ParallelHash256 } else { Identity::ParallelHash128 };
        let mut plan = Plan::new(identity, &[], 1, 1).unwrap().with_worker_policy(workers);
        plan.leaves = total;
        let mut other = Plan::new(identity, &[], 1, 1).unwrap().with_worker_policy(workers);
        other.leaves = total;
        let state = if backend_failure {
            State::Portable256(brynja_hash_sha3::HardenedCshake256::new(&[], &[]).unwrap())
        } else {
            State::Portable128(brynja_hash_sha3::HardenedCshake128::new(&[], &[]).unwrap())
        };
        let mut root = Collector {
            binding: if streaming {
                Binding::Streaming { identity, block: 1, limit: total, workers }
            } else { Binding::Scheduled(&plan) },
            state, merged: position.to_le_bytes(), accelerated: accelerated.to_le_bytes(),
            output_bits: [0; 16], phase: [phase],
        };
        let mut slots: [[u8; 64]; 4] = kani::any();
        let token = batch::TransferredLeaves::qualification_token(
            if foreign { &other } else { &plan }, start, count, mask, &mut slots,
        );
        let result = root.merge_transferred(token);
        // Subtraction-based independent admission and overflow oracle.
        let vector_count = u128::from(mask.count_ones());
        let valid = !backend_failure && !streaming && phase == 1 && !foreign && start == position
            && count >= 1 && count <= 4 && start <= total
            && (count as u128) <= total - start
            && (policy == 0 || (policy == 1 && mask == 0) || (policy == 2 && mask == active))
            && vector_count <= u128::MAX - accelerated;
        assert_eq!(result.is_ok(), valid);
        if valid {
            assert_eq!(root.merged_leaves(), start + count as u128);
            assert_eq!(root.accelerated_leaves(), accelerated + vector_count);
            assert_eq!(root.phase, [1]);
        } else {
            assert_eq!(root.phase, [0]);
            assert_eq!(root.merged_leaves(), 0);
            assert_eq!(root.accelerated_leaves(), 0);
        }
        // Token consumption must clear even inactive slots and short-CV tails.
        let slot: usize = kani::any();
        let byte: usize = kani::any();
        kani::assume(slot < 4 && byte < 64);
        assert_eq!(slots[slot][byte], 0);
    }
    #[kani::proof]
    #[kani::stub(crate::execution::backend::State::update, absorb)]
    #[kani::stub(brynja_core::secret_memory_volatile::zeroize_region_volatile, clear)]
    #[kani::unwind(33)]
    fn narrow_transfer_consumption() { check(false); }
    #[kani::proof]
    #[kani::stub(crate::execution::backend::State::update, absorb)]
    #[kani::stub(brynja_core::secret_memory_volatile::zeroize_region_volatile, clear)]
    #[kani::unwind(33)]
    fn wide_transfer_consumption() { check(true); }
}
'''

SOURCES = {
    'execution/batch/transfer.rs': TRANSFER_SETUP,
    'execution/collector/batch.rs': MERGE,
}
HARNESSES = {
    'transfer': 'execution::collector::batch::transfer_qualification::narrow_transfer_consumption',
    'transfer-wide': 'execution::collector::batch::transfer_qualification::wide_transfer_consumption',
}
# Anchors are unique to merge_transferred; several checks also occur in
# merge_batch and must not accidentally be mutated there.
MUTANTS = (
    ('transfer', 'execution/collector/batch.rs', '|| !core::ptr::eq(bound, leaves.plan)', ''),
    ('transfer', 'execution/collector/batch.rs', '|| leaves.start != position', ''),
    ('transfer', 'execution/collector/batch.rs',
     '|| leaves.start != position\n            || leaves.count == 0',
     '|| leaves.start != position'),
    ('transfer', 'execution/collector/batch.rs', '|| end > bound.leaf_count()', ''),
    ('transfer', 'execution/collector/batch.rs', 'WorkerPolicy::Portable => !vector,', 'WorkerPolicy::Portable => true,'),
    ('transfer', 'execution/collector/batch.rs',
     'let next_accelerated = root\n            .accelerated_leaves()\n            .checked_add(u128::from(leaves.report.accelerated_slots.count_ones()))\n            .ok_or(RootError::State)?;',
     'let next_accelerated = root.accelerated_leaves().wrapping_add(u128::from(leaves.report.accelerated_slots.count_ones()));'),
    ('transfer', 'execution/collector/batch.rs', 'root.merged = end.to_le_bytes();', 'root.merged = position.to_le_bytes();'),
    ('transfer-wide', 'execution/collector/batch.rs',
     'WorkerPolicy::RequireAcceleration => vector,', 'WorkerPolicy::RequireAcceleration => true,'),
    ('transfer', 'execution/batch/transfer.rs',
     'clear_owned_region(self.values.as_flattened_mut())',
     'clear_owned_region(self.values[..3].as_flattened_mut())'),
)
