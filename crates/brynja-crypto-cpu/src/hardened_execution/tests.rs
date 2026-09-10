use super::*;

#[test]
fn scratch_regions_clear_on_explicit_wipe_and_unwind() -> Result<(), std::string::String> {
    let mut scratch = Scratch::new();
    scratch.schedule.fill(0xa5);
    scratch.vectors.fill(0x5a);
    scratch.wipe();
    assert!(
        scratch
            .schedule
            .iter()
            .chain(&scratch.vectors)
            .all(|b| *b == 0)
    );
    for kernel in [Kernel::X86Sha256, Kernel::ArmSha256, Kernel::ArmSha512] {
        let Ok(owner) = raw::Authority::new(kernel) else {
            continue;
        };
        let route = Route::Static(owner.session().map_err(|error| std::format!("{error:?}"))?);
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let guard = Operation {
                scratch: &mut scratch,
                route: &route,
                completed: false,
            };
            guard.scratch.schedule.fill(0x39);
            guard.scratch.vectors.fill(0x93);
            std::panic::resume_unwind(std::boxed::Box::new("recoverable kernel unwind probe"));
        }));
        assert!(result.is_err());
        assert!(
            scratch
                .schedule
                .iter()
                .chain(&scratch.vectors)
                .all(|b| *b == 0)
        );
        assert_eq!(owner.report().health, raw::Health::Quarantined);
    }
    Ok(())
}

#[test]
fn hardened_kernel_matches_ordinary_and_clears_every_operation() -> Result<(), std::string::String>
{
    let mut runs = 0_usize;
    for kernel in [Kernel::X86Sha256, Kernel::ArmSha256, Kernel::ArmSha512] {
        let Ok(owner) = raw::Authority::new(kernel) else {
            continue;
        };
        let wide = kernel == Kernel::ArmSha512;
        let mut session =
            Session::from_static(&owner).map_err(|error| std::format!("{error:?}"))?;
        let ordinary = owner.session().map_err(|error| std::format!("{error:?}"))?;
        let mut generator = 0x7654_3210_abcd_ef01_u64;
        for _ in 0..512 {
            let mut state = [0_u8; 64];
            let mut block = [0_u8; 128];
            for b in state.iter_mut().chain(block.iter_mut()) {
                generator ^= generator << 13;
                generator ^= generator >> 7;
                generator ^= generator << 17;
                *b = generator.to_le_bytes()[0];
            }
            let before = state;
            assert_eq!(
                session.compress(!wide, &mut state, &block),
                Err(Error::WrongOperation)
            );
            assert_eq!(state, before);
            let mut expected = state;
            if wide {
                let mut words = [0_u64; 8];
                for (word, bytes) in words.iter_mut().zip(state.chunks_exact(8)) {
                    *word = u64::from_be_bytes(
                        bytes
                            .try_into()
                            .map_err(|error| std::format!("{error:?}"))?,
                    );
                }
                ordinary
                    .compress_sha512(
                        raw::PublicData::new(&mut words),
                        raw::PublicData::new(&block),
                    )
                    .map_err(|error| std::format!("{error:?}"))?;
                for (bytes, word) in expected.chunks_exact_mut(8).zip(words) {
                    bytes.copy_from_slice(&word.to_be_bytes());
                }
            } else {
                let mut words = [0_u32; 8];
                for (word, bytes) in words.iter_mut().zip(state.chunks_exact(4)) {
                    *word = u32::from_be_bytes(
                        bytes
                            .try_into()
                            .map_err(|error| std::format!("{error:?}"))?,
                    );
                }
                ordinary
                    .compress_sha256(
                        raw::PublicData::new(&mut words),
                        raw::PublicData::new(
                            block[..64]
                                .try_into()
                                .map_err(|error| std::format!("{error:?}"))?,
                        ),
                    )
                    .map_err(|error| std::format!("{error:?}"))?;
                for (bytes, word) in expected.chunks_exact_mut(4).zip(words) {
                    bytes.copy_from_slice(&word.to_be_bytes());
                }
            }
            session
                .compress(wide, &mut state, &block)
                .map_err(|error| std::format!("{error:?}"))?;
            assert_eq!(state, expected);
            assert!(
                session
                    .scratch
                    .schedule
                    .iter()
                    .chain(&session.scratch.vectors)
                    .all(|b| *b == 0)
            );
        }
        owner.quarantine();
        let mut state = [0xa5; 64];
        assert_eq!(
            session.compress(wide, &mut state, &[0; 128]),
            Err(Error::Quarantined)
        );
        assert_eq!(state, [0xa5; 64]);
        runs = runs.saturating_add(1);
    }
    #[cfg(all(target_arch = "x86_64", target_feature = "sha"))]
    assert_eq!(runs, 1);
    #[cfg(all(
        target_arch = "aarch64",
        target_feature = "sha2",
        target_feature = "sha3"
    ))]
    assert_eq!(runs, 2);
    let _ = runs;
    Ok(())
}
