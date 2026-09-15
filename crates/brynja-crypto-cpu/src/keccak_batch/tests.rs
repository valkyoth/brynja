use super::*;
extern crate std;

// Independent scalar round layout: derive rho offsets and iota constants instead
// of sharing the production tables, and check the zero-state published vector.
fn reference(a: &mut [u64; 25]) -> Result<(), Error> {
    fn index(x: usize, y: usize) -> usize {
        x.saturating_add(y.saturating_mul(5))
    }
    fn at(a: &[u64; 25], x: usize, y: usize) -> Result<u64, Error> {
        a.get(index(x, y)).copied().ok_or(Error::Invariant)
    }
    let mut rho = [0_u32; 25];
    let (mut x, mut y) = (1_usize, 0_usize);
    for t in 0_u32..24 {
        *rho.get_mut(index(x, y)).ok_or(Error::Invariant)? =
            t.saturating_add(1).saturating_mul(t.saturating_add(2)) / 2 % 64;
        (x, y) = (
            y,
            x.saturating_mul(2).saturating_add(y.saturating_mul(3)) % 5,
        );
    }
    let mut lfsr = 1_u8;
    for _ in 0..24 {
        let mut c = [0_u64; 5];
        for (x, column) in c.iter_mut().enumerate() {
            for y in 0..5 {
                *column ^= at(a, x, y)?;
            }
        }
        for x in 0_usize..5 {
            let delta = c.get(x.saturating_add(4) % 5).ok_or(Error::Invariant)?
                ^ c.get(x.saturating_add(1) % 5)
                    .ok_or(Error::Invariant)?
                    .rotate_left(1);
            for y in 0..5 {
                *a.get_mut(index(x, y)).ok_or(Error::Invariant)? ^= delta;
            }
        }
        let mut b = [0_u64; 25];
        for x in 0_usize..5 {
            for y in 0_usize..5 {
                let target = index(
                    y,
                    x.saturating_mul(2).saturating_add(y.saturating_mul(3)) % 5,
                );
                *b.get_mut(target).ok_or(Error::Invariant)? =
                    at(a, x, y)?.rotate_left(*rho.get(index(x, y)).ok_or(Error::Invariant)?);
            }
        }
        for x in 0_usize..5 {
            for y in 0..5 {
                *a.get_mut(index(x, y)).ok_or(Error::Invariant)? = at(&b, x, y)?
                    ^ (!at(&b, x.saturating_add(1) % 5, y)? & at(&b, x.saturating_add(2) % 5, y)?);
            }
        }
        for j in 0..7 {
            if lfsr & 1 != 0 {
                *a.first_mut().ok_or(Error::Invariant)? ^= 1_u64 << (1_u32 << j).saturating_sub(1);
            }
            lfsr = lfsr.wrapping_shl(1) ^ if lfsr & 0x80 != 0 { 0x71 } else { 0 };
        }
    }
    Ok(())
}

#[test]
fn reference_matches_zero_state_kat() -> Result<(), Error> {
    let mut state = [0; 25];
    reference(&mut state)?;
    assert_eq!(state, crate::keccak_constants::ZERO_STATE_RESULT);
    Ok(())
}

#[test]
fn absent_static_bundle_rejects() {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            assert!(Authority::for_compiled_target(kernel).is_err());
        }
    }
}

#[test]
fn compiled_kernel_differential_and_inactive_lanes() -> Result<(), Error> {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        let owner = Authority::for_compiled_target(kernel)?;
        let session = owner.session()?;
        assert_eq!(session.completed_vector_calls(), 0);
        let mut random = 0x9162_d41b_02ec_a731_u64;
        for n in 0..1024 {
            let mut states = [[0; 25]; 4];
            for state in &mut states {
                for word in state {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    *word = random;
                }
            }
            let mut expected = states;
            for state in expected.iter_mut().take(kernel.width()) {
                reference(state)?;
            }
            session.permute(PublicData::new(&mut states))?;
            assert_eq!(states, expected, "case {n}, kernel {kernel:?}");
        }
        assert_eq!(session.completed_vector_calls(), 1024);
        std::println!(
            "KECCAK_BATCH_NATIVE: {kernel:?}; calls=1024; width={}",
            kernel.width()
        );
        let mut states = [[42; 25]; 4];
        owner.completed_calls.set(u64::MAX);
        assert_eq!(
            session.permute(PublicData::new(&mut states)),
            Err(Error::Invariant)
        );
        assert_eq!(states, [[42; 25]; 4]);
        assert!(!owner.is_healthy());
    }
    Ok(())
}

fn untested_owner(kernel: Kernel, revalidate: fn(Kernel) -> bool) -> Authority {
    Authority {
        kernel,
        healthy: Cell::new(true),
        completed_calls: Cell::new(0),
        revalidate,
        thread_bound: PhantomData,
    }
}

#[test]
fn failed_revalidation_and_unwind_are_atomic_and_terminal() {
    for revalidate in [reject as fn(Kernel) -> bool, unwind] {
        let owner = untested_owner(Kernel::Avx2, revalidate);
        let session = Session { owner: &owner };
        let mut states = [[17; 25]; 4];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            session.permute(PublicData::new(&mut states))
        }));
        assert!(matches!(result, Err(_) | Ok(Err(Error::Quarantined))));
        assert_eq!(states, [[17; 25]; 4]);
        assert_eq!(owner.completed_calls.get(), 0);
        assert!(!owner.is_healthy());
        assert!(owner.session().is_err());
    }
}
fn reject(_: Kernel) -> bool {
    false
}
fn unwind(_: Kernel) -> bool {
    std::panic::resume_unwind(std::boxed::Box::new("revalidator"))
}

std::thread_local! { static CHECKS: Cell<u32> = const { Cell::new(0) }; }
fn revoke_after_entry(_: Kernel) -> bool {
    CHECKS.with(|checks| {
        let n = checks.get();
        checks.set(n.saturating_add(1));
        n == 0
    })
}
#[test]
fn post_dispatch_revocation_preserves_all_states() {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        CHECKS.with(|c| c.set(0));
        let owner = untested_owner(kernel, revoke_after_entry);
        let session = Session { owner: &owner };
        let mut states = [[99; 25]; 4];
        assert_eq!(
            session.permute(PublicData::new(&mut states)),
            Err(Error::Quarantined)
        );
        assert_eq!(states, [[99; 25]; 4]);
        assert_eq!(session.completed_vector_calls(), 0);
        assert!(!owner.is_healthy());
    }
}
