use super::*;

fn fill(s: &mut KeccakScratch) {
    s.lanes.fill(0xa5);
    s.columns.fill(0xb6);
    s.theta.fill(0xc7);
    s.rearranged.fill(0xd8);
    s.current.fill(0xe9);
    s.next.fill(0xfa);
    s.following.fill(0x9b);
}

fn is_clear(s: &KeccakScratch) -> bool {
    [
        &s.lanes[..],
        &s.columns,
        &s.theta,
        &s.rearranged,
        &s.current,
        &s.next,
        &s.following,
    ]
    .into_iter()
    .all(|region| region.iter().all(|byte| *byte == 0))
}

#[test]
fn all_seven_regions_clear() {
    let mut scratch = KeccakScratch::new();
    fill(&mut scratch);
    scratch.wipe();
    assert!(is_clear(&scratch));
}

#[test]
fn hardened_keccak_matches_ordinary_without_leaving_scratch() -> Result<(), Error> {
    let mut executed = 0;
    for kernel in [Kernel::X86Keccak, Kernel::ArmKeccak] {
        let Ok(owner) = raw::Authority::new(kernel) else {
            continue;
        };
        let mut session = KeccakSession::from_static(&owner)?;
        let ordinary = owner.session()?;
        assert!(is_clear(&session.scratch));
        let mut generator = 0x7654_3210_abcd_ef01_u64;
        for _ in 0..1024 {
            let mut state = [0_u8; 200];
            for byte in &mut state {
                generator ^= generator << 13;
                generator ^= generator >> 7;
                generator ^= generator << 17;
                *byte = generator.to_le_bytes()[0];
            }
            let mut expected = [0_u64; 25];
            for (word, bytes) in expected.iter_mut().zip(state.as_chunks::<8>().0) {
                *word = u64::from_le_bytes(*bytes);
            }
            ordinary.permute_keccak(raw::PublicData::new(&mut expected))?;
            session.permute(&mut state)?;
            for (word, bytes) in expected.into_iter().zip(state.as_chunks::<8>().0) {
                assert_eq!(u64::from_le_bytes(*bytes), word);
            }
            assert!(is_clear(&session.scratch));
        }
        owner.quarantine();
        let mut state = [0x93; 200];
        assert_eq!(session.permute(&mut state), Err(Error::Quarantined));
        assert_eq!(state, [0x93; 200]);
        assert!(is_clear(&session.scratch));
        std::println!("HARDENED_KECCAK_EXECUTION: {kernel:?}; permutations=1024");
        executed += 1;
    }
    #[cfg(any(
        all(target_arch = "x86_64", target_feature = "avx2"),
        all(target_arch = "aarch64", target_feature = "sha3")
    ))]
    assert_eq!(executed, 1);
    let _ = executed;
    Ok(())
}

#[test]
fn unwind_clears_scratch_and_quarantines_owner() -> Result<(), Error> {
    for kernel in [Kernel::X86Keccak, Kernel::ArmKeccak] {
        let Ok(owner) = raw::Authority::new(kernel) else {
            continue;
        };
        let mut scratch = KeccakScratch::new();
        let route = Route::Static(owner.session()?);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let guard = Operation {
                scratch: &mut scratch,
                route: &route,
                completed: false,
            };
            fill(guard.scratch);
            std::panic::resume_unwind(std::boxed::Box::new("hardened Keccak unwind"));
        }));
        assert!(result.is_err());
        assert!(is_clear(&scratch));
        assert_eq!(owner.report().health, raw::Health::Quarantined);
    }
    Ok(())
}

#[test]
fn sha2_authority_cannot_enter_keccak() -> Result<(), Error> {
    for kernel in [Kernel::X86Sha256, Kernel::ArmSha256, Kernel::ArmSha512] {
        if let Ok(owner) = raw::Authority::new(kernel) {
            assert!(matches!(
                KeccakSession::from_static(&owner),
                Err(Error::WrongOperation)
            ));
            assert_eq!(owner.report().health, raw::Health::Healthy);
        }
    }
    Ok(())
}
