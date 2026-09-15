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

std::thread_local! {
    static DROPS: Cell<usize> = const { Cell::new(0) };
    static CALLS: Cell<usize> = const { Cell::new(0) };
}
fn cleared(s: &Workspace) {
    assert_eq!(s.state, [[0; 32]; 25]);
    assert_eq!(s.columns, [[0; 32]; 5]);
    assert_eq!(s.deltas, [[0; 32]; 5]);
    assert_eq!(s.staging, [[0; 32]; 25]);
}
fn dirty(s: &mut Workspace) {
    s.state.fill([0xa1; 32]);
    s.columns.fill([0xa2; 32]);
    s.deltas.fill([0xa3; 32]);
    s.staging.fill([0xa4; 32]);
}
pub(super) fn observe_drop(s: &Workspace) {
    let clean = s
        .state
        .iter()
        .chain(&s.columns)
        .chain(&s.deltas)
        .chain(&s.staging)
        .all(|row| row.iter().all(|b| *b == 0));
    DROPS.with(|n| {
        n.set(if clean {
            n.get().saturating_add(1)
        } else {
            usize::MAX
        })
    });
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
fn reject(_: Kernel) -> bool {
    false
}
fn unwind(_: Kernel) -> bool {
    std::panic::resume_unwind(std::boxed::Box::new("revalidation"))
}
fn second_reject(_: Kernel) -> bool {
    CALLS.with(|n| {
        n.set(n.get().saturating_add(1));
        n.get() != 2
    })
}
fn second_unwind(k: Kernel) -> bool {
    if second_reject(k) { true } else { unwind(k) }
}
#[test]
fn every_region_clears_explicitly_and_on_drop() {
    let mut s = Workspace::new();
    dirty(&mut s);
    s.clear();
    cleared(&s);
    dirty(&mut s);
    let before = DROPS.with(Cell::get);
    drop(s);
    assert_eq!(DROPS.with(Cell::get), before.saturating_add(1));
}
#[test]
fn invalid_widths_reject_and_clear_both_imports() {
    let mut s = Workspace::new();
    for width in [0, 1, 3, 5, usize::MAX] {
        dirty(&mut s);
        assert_eq!(s.pack(&[[1; 25]; 4], width), Err(Error::Invariant));
        cleared(&s);
        dirty(&mut s);
        assert_eq!(s.pack_bytes(&[[1; 200]; 4], width), Err(Error::Invariant));
        cleared(&s);
    }
}
#[test]
fn pack_commit_roundtrips_and_preserves_inactive_capacity() -> Result<(), Error> {
    let words = core::array::from_fn(|lane| {
        core::array::from_fn(|word| {
            (lane as u64)
                .wrapping_mul(0xf102_3456_789a_bcde)
                .wrapping_add(word as u64)
        })
    });
    let bytes = encode(&words);
    for width in [2, 4] {
        let mut s = Workspace::new();
        s.pack(&words, width)?;
        let mut out = [[7; 25]; 4];
        s.commit(&mut out, width);
        for (i, (state, expected)) in out.iter().zip(&words).enumerate() {
            assert_eq!(*state, if i < width { *expected } else { [7; 25] });
        }
        s.pack_bytes(&bytes, width)?;
        let mut out = [[7; 200]; 4];
        s.commit_bytes(&mut out, width);
        for (i, (state, expected)) in out.iter().zip(&bytes).enumerate() {
            assert_eq!(*state, if i < width { *expected } else { [7; 200] });
        }
        for row in &s.state {
            assert!(
                row.get(width * 8..)
                    .ok_or(Error::Invariant)?
                    .iter()
                    .all(|v| *v == 0)
            );
        }
        s.clear();
        cleared(&s);
    }
    Ok(())
}
fn encode(words: &[[u64; 25]; 4]) -> [[u8; 200]; 4] {
    let mut bytes = [[0; 200]; 4];
    for (out, state) in bytes.iter_mut().zip(words) {
        for (out, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(state) {
            *out = word.to_le_bytes();
        }
    }
    bytes
}
#[test]
fn native_word_and_byte_entries_match_independent_reference() -> Result<(), Error> {
    let mut executed = false;
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        executed = true;
        let authority = Authority::for_compiled_target(kernel)?;
        let session = authority.session()?;
        let mut s = Workspace::new();
        let mut random = 0x9162_d41b_02ec_a731_u64;
        for case in 0..1024 {
            let mut states = [[0; 25]; 4];
            for state in &mut states {
                for word in state {
                    random ^= random << 13;
                    random ^= random >> 7;
                    random ^= random << 17;
                    *word = random;
                }
            }
            let mut bytes = encode(&states);
            let mut expected = states;
            for state in expected.iter_mut().take(kernel.width()) {
                reference(state)?;
            }
            dirty(&mut s);
            session.permute(&mut states, &mut s)?;
            assert_eq!(states, expected, "word case {case}");
            cleared(&s);
            dirty(&mut s);
            session.permute_bytes(&mut bytes, &mut s)?;
            assert_eq!(bytes, encode(&expected), "byte case {case}");
            cleared(&s);
        }
        assert_eq!(session.completed_vector_calls(), 2048);
        std::println!("HARDENED_KECCAK_BATCH_NATIVE: {kernel:?}; pairs=1024");
    }
    if std::env::var_os("BRYNJA_REQUIRE_KECCAK_HARDENED_BATCH").is_some() {
        assert!(executed);
    }
    Ok(())
}
#[test]
fn preflight_rejection_and_unwind_clear_and_quarantine() {
    for revalidate in [reject as fn(Kernel) -> bool, unwind] {
        for bytes in [false, true] {
            let authority = owner(Kernel::Avx2, revalidate);
            let session = Session { owner: &authority };
            let mut s = Workspace::new();
            dirty(&mut s);
            let mut words = [[11; 25]; 4];
            let mut octets = [[12; 200]; 4];
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                if bytes {
                    session.permute_bytes(&mut octets, &mut s)
                } else {
                    session.permute(&mut words, &mut s)
                }
            }));
            assert!(matches!(result, Err(_) | Ok(Err(Error::Quarantined))));
            assert_eq!(words, [[11; 25]; 4]);
            assert_eq!(octets, [[12; 200]; 4]);
            cleared(&s);
            assert!(!authority.is_healthy());
            assert!(authority.session().is_err());
        }
    }
}
#[test]
fn post_dispatch_failure_and_overflow_preserve_caller_states() -> Result<(), Error> {
    for kernel in [Kernel::Avx2, Kernel::Neon] {
        if !kernel.compiled() {
            continue;
        }
        for (mode, revalidate) in [
            second_reject as fn(Kernel) -> bool,
            second_unwind,
            Kernel::compiled,
        ]
        .into_iter()
        .enumerate()
        {
            for bytes in [false, true] {
                CALLS.with(|n| n.set(0));
                let authority = owner(kernel, revalidate);
                let before = if mode == 2 { u64::MAX } else { 0 };
                authority.completed.set(before);
                let session = Session { owner: &authority };
                let mut s = Workspace::new();
                dirty(&mut s);
                let mut words = [[11; 25]; 4];
                let mut octets = [[12; 200]; 4];
                let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                    if bytes {
                        session.permute_bytes(&mut octets, &mut s)
                    } else {
                        session.permute(&mut words, &mut s)
                    }
                }));
                assert!(matches!(
                    result,
                    Err(_) | Ok(Err(Error::Quarantined | Error::Invariant))
                ));
                assert_eq!(words, [[11; 25]; 4]);
                assert_eq!(octets, [[12; 200]; 4]);
                assert_eq!(authority.completed.get(), before);
                cleared(&s);
                assert!(!authority.is_healthy());
            }
        }
    }
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
