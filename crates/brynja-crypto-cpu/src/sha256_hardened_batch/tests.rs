use super::*;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};

fn poison(s: &mut Workspace) {
    s.initial.as_flattened_mut().fill(0xa5);
    s.schedule.as_flattened_mut().fill(0x5a);
    s.work.as_flattened_mut().fill(0x69);
    s.temporary.as_flattened_mut().fill(0x96);
}
fn cleared(s: &Workspace) {
    assert_eq!(s.initial, [[0; 32]; 8]);
    assert_eq!(s.schedule, [[0; 32]; 64]);
    assert_eq!(s.work, [[0; 32]; 8]);
    assert_eq!(s.temporary, [[0; 32]; 6]);
}
fn owner(kernel: Kernel, revalidate: fn(Kernel) -> bool) -> Authority {
    Authority {
        kernel,
        healthy: Cell::new(true),
        completed: Cell::new(0),
        revalidate,
        thread_bound: PhantomData,
    }
}
std::thread_local! {
    static REMAINING: Cell<usize> = const { Cell::new(0) };
    static PANIC: Cell<bool> = const { Cell::new(false) };
    static DROP_CLEARED: Cell<bool> = const { Cell::new(false) };
}
pub(super) fn observe_drop(workspace: &Workspace) {
    let all_zero = workspace
        .initial
        .iter()
        .chain(&workspace.schedule)
        .chain(&workspace.work)
        .chain(&workspace.temporary)
        .flatten()
        .all(|byte| *byte == 0);
    DROP_CLEARED.with(|flag| flag.set(all_zero));
}
#[test]
fn destructor_clears_poisoned_storage() {
    DROP_CLEARED.with(|flag| flag.set(false));
    let mut workspace = Workspace::new();
    poison(&mut workspace);
    drop(workspace);
    assert!(DROP_CLEARED.with(Cell::get));
}
fn revokes(_: Kernel) -> bool {
    REMAINING.with(|left| {
        if left.get() == 0 {
            if PANIC.with(Cell::get) {
                resume_unwind(Box::new("revalidation probe"));
            }
            false
        } else {
            left.set(left.get().saturating_sub(1));
            true
        }
    })
}
#[test]
fn cleanup_all_four_regions_and_inactive_capacity() {
    let mut workspace = Workspace::new();
    poison(&mut workspace);
    workspace.wipe();
    cleared(&workspace);
    workspace.wipe();
    cleared(&workspace);
}
#[test]
fn pack_rejects_invalid_width_and_initializes_inactive_lanes() -> Result<(), Error> {
    let mut workspace = Workspace::new();
    let states = [[0x12345678; 8]; 8];
    let blocks = [[0x91; 64]; 8];
    for width in [0, 1, 3, 5, 7, 9, usize::MAX] {
        poison(&mut workspace);
        assert_eq!(
            workspace.pack(&states, &blocks, width),
            Err(Error::Invariant)
        );
        cleared(&workspace);
    }
    poison(&mut workspace);
    workspace.pack(&states, &blocks, 4)?;
    for packed in workspace.initial.iter().chain(&workspace.schedule) {
        assert!(packed.iter().skip(16).all(|byte| *byte == 0));
    }
    workspace.wipe();
    cleared(&workspace);
    Ok(())
}
#[test]
fn rejection_and_unwind_clear_before_any_instruction() {
    let mut workspace = Workspace::new();
    let mut states = [[0xdeadbeef; 8]; 8];
    let blocks = [[0x7c; 64]; 8];
    for panic in [false, true] {
        let authority = owner(Kernel::Avx2, revokes);
        let session = Session { owner: &authority };
        poison(&mut workspace);
        REMAINING.with(|left| left.set(0));
        PANIC.with(|flag| flag.set(panic));
        let outcome = catch_unwind(AssertUnwindSafe(|| {
            session.compress(&mut states, &blocks, &mut workspace)
        }));
        if panic {
            assert!(outcome.is_err());
        } else {
            assert!(matches!(outcome, Ok(Err(Error::Quarantined))));
        }
        assert_eq!(states, [[0xdeadbeef; 8]; 8]);
        assert!(!authority.is_healthy());
        assert_eq!(authority.completed.get(), 0);
        cleared(&workspace);
    }
    PANIC.with(|flag| flag.set(false));
}
#[test]
fn operation_unwind_clears_partially_populated_workspace() {
    let authority = owner(Kernel::Avx2, |_| true);
    let mut workspace = Workspace::new();
    assert!(
        catch_unwind(AssertUnwindSafe(|| {
            let guard = Operation {
                health: HealthGuard {
                    owner: &authority,
                    complete: false,
                },
                workspace: &mut workspace,
            };
            poison(guard.workspace);
            resume_unwind(Box::new("partial operation"));
        }))
        .is_err()
    );
    assert!(!authority.is_healthy());
    cleared(&workspace);
}
#[test]
fn unsupported_static_bundle_never_constructs_authority() {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.architecture() {
            assert!(matches!(
                Authority::for_compiled_target(kernel),
                Err(Error::WrongArchitecture)
            ));
        } else if !kernel.compiled() {
            assert!(matches!(
                Authority::for_compiled_target(kernel),
                Err(Error::MissingFeatures)
            ));
        }
    }
}

// Test-only scalar formulation. Neither production routing nor the startup KAT
// uses this reference. Differential inputs below vary every state and lane.
fn reference(state: &mut [u32; 8], block: &[u8; 64]) -> Result<(), Error> {
    let mut w = [0_u32; 64];
    for (word, bytes) in w.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    for i in 16_usize..64 {
        let a = *w.get(i.saturating_sub(15)).ok_or(Error::Invariant)?;
        let b = *w.get(i.saturating_sub(2)).ok_or(Error::Invariant)?;
        let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3);
        let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10);
        let value = w
            .get(i.saturating_sub(16))
            .ok_or(Error::Invariant)?
            .wrapping_add(s0)
            .wrapping_add(*w.get(i.saturating_sub(7)).ok_or(Error::Invariant)?)
            .wrapping_add(s1);
        *w.get_mut(i).ok_or(Error::Invariant)? = value;
    }
    let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = *state;
    for (word, constant) in w.into_iter().zip(crate::sha256_schedule::ROUND_CONSTANTS) {
        let t1 = h
            .wrapping_add(e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25))
            .wrapping_add((e & f) ^ (!e & g))
            .wrapping_add(constant)
            .wrapping_add(word);
        let t2 = (a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22))
            .wrapping_add((a & b) ^ (a & c) ^ (b & c));
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    for (before, after) in state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
        *before = before.wrapping_add(after);
    }
    Ok(())
}
fn next(seed: &mut u32) -> u32 {
    *seed ^= seed.wrapping_shl(13);
    *seed ^= seed.wrapping_shr(17);
    *seed ^= seed.wrapping_shl(5);
    *seed
}
#[test]
fn native_lane_distinct_differential_and_actual_dispatch() -> Result<(), Error> {
    let mut known = crate::sha256::initial_state();
    reference(&mut known, &crate::sha256::abc_block())?;
    assert_eq!(known, crate::sha256::abc_digest_state());
    let mut executed = 0_u64;
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let authority = Authority::for_compiled_target(kernel)?;
        let session = authority.session()?;
        assert_eq!(session.completed_vector_calls(), 0);
        let mut workspace = Workspace::new();
        let mut seed = 0x8a914503;
        for _ in 0..512 {
            let mut states = [[0; 8]; 8];
            let mut blocks = [[0; 64]; 8];
            for state in &mut states {
                for word in state {
                    *word = next(&mut seed);
                }
            }
            for block in &mut blocks {
                for byte in block {
                    *byte = next(&mut seed)
                        .to_le_bytes()
                        .into_iter()
                        .next()
                        .ok_or(Error::Invariant)?;
                }
            }
            let mut expected = states;
            for (state, block) in expected.iter_mut().zip(&blocks).take(kernel.width()) {
                reference(state, block)?;
            }
            poison(&mut workspace);
            session.compress(&mut states, &blocks, &mut workspace)?;
            assert_eq!(states, expected);
            cleared(&workspace);
            executed = executed.checked_add(1).ok_or(Error::Invariant)?;
        }
        assert_eq!(session.completed_vector_calls(), 512);
        assert!(authority.is_healthy());
    }
    if std::env::var_os("BRYNJA_REQUIRE_SHA256_HARDENED_BATCH").is_some() {
        assert_eq!(executed, 512);
    }
    Ok(())
}
#[test]
fn post_dispatch_health_loss_unwind_and_counter_overflow_are_transactional() -> Result<(), Error> {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        for panic in [false, true] {
            let authority = owner(kernel, revokes);
            REMAINING.with(|left| left.set(1));
            PANIC.with(|flag| flag.set(panic));
            let session = Session { owner: &authority };
            let mut workspace = Workspace::new();
            let mut states = [crate::sha256::initial_state(); 8];
            let before = states;
            let result = catch_unwind(AssertUnwindSafe(|| {
                session.compress(
                    &mut states,
                    &[crate::sha256::abc_block(); 8],
                    &mut workspace,
                )
            }));
            if panic {
                assert!(result.is_err());
            } else {
                assert!(matches!(result, Ok(Err(Error::Quarantined))));
            }
            assert_eq!(states, before);
            assert!(!authority.is_healthy());
            cleared(&workspace);
        }
        PANIC.with(|flag| flag.set(false));
        let authority = Authority::for_compiled_target(kernel)?;
        authority.completed.set(u64::MAX);
        let session = authority.session()?;
        let mut states = [crate::sha256::initial_state(); 8];
        let before = states;
        let mut workspace = Workspace::new();
        assert_eq!(
            session.compress(
                &mut states,
                &[crate::sha256::abc_block(); 8],
                &mut workspace
            ),
            Err(Error::Invariant)
        );
        assert_eq!(states, before);
        assert_eq!(session.completed_vector_calls(), u64::MAX);
        assert!(!authority.is_healthy());
        cleared(&workspace);
    }
    Ok(())
}
