//! Public-fixture import observations. An import error is not owner retirement:
//! no usable owner is returned. The external observer must require rejection
//! for its selected mutations; accepting either outcome here is not evidence.
use super::*;

macro_rules! import_runner {
    ($run:ident, $owner:ty, $kind:literal) => {
        #[inline(never)]
        fn $run(width: usize) -> Result<bool, Error> {
            let plain = tests::answer("00112233445566778899aabbccddeeff")?;
            let cipher = tests::answer(match width {
                16 => "69c4e0d86a7b0430d8cdb78070b4c55a",
                24 => "dda97ca4864cdfe06eaf70a0ec0d7191",
                32 => "8ea2b7ca516745bfeafc49904b496089",
                _ => return Err(Error::SecretMemory),
            })?;
            std::println!(
                "BRYNJA_IMPORT_{}_EVIDENCE_CFG={}",
                $kind,
                cfg!(brynja_fault_evidence)
            );
            std::println!("BRYNJA_IMPORT_{}_WIDTH={width}", $kind);
            let mut key = [0; 32];
            for (byte, value) in key.iter_mut().zip(0u8..32) {
                *byte = value;
            }
            let original = key;
            let mut primary = [0x91; 34];
            let mut secondary = [0x92; 34];
            let end = width.wrapping_add(1);
            let mut output = [0x93; 16];
            let accepted;
            {
                let imported = <$owner>::new_profile(
                    black_box(key.get(..width).ok_or(Error::SecretMemory)?),
                    primary.get_mut(1..end).ok_or(Error::SecretMemory)?,
                    secondary.get_mut(1..end).ok_or(Error::SecretMemory)?,
                );
                accepted = match imported {
                    Ok(mut owner) => {
                        black_box(&mut owner).encrypt_public(
                            &plain,
                            &mut output,
                            PublicCiphertext::acknowledge(),
                        )?;
                        assert_eq!(output, cipher);
                        let block = owner.secret(&plain, &mut output, false)?;
                        assert_eq!(block.expose(), &cipher);
                        block.clear();
                        assert_eq!(output, [0; 16]);
                        let block = owner.secret(&cipher, &mut output, true)?;
                        assert_eq!(block.expose(), &plain);
                        drop(block);
                        assert_eq!(output, [0; 16]);
                        true
                    }
                    Err(error) => {
                        assert_eq!(error, ProfileFailure::ImportRejected);
                        assert_eq!(output, [0x93; 16]);
                        false
                    }
                };
            }
            assert_eq!(key, original);
            for (storage, sentinel) in [(&primary, 0x91), (&secondary, 0x92)] {
                assert!(
                    storage
                        .get(1..end)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|v| *v == 0)
                );
                assert_eq!(storage.first(), Some(&sentinel));
                assert!(
                    storage
                        .get(end..)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|v| *v == sentinel)
                );
            }
            std::println!("BRYNJA_IMPORT_{}_SOURCE_AND_GUARDS_INTACT", $kind);
            std::println!("BRYNJA_IMPORT_{}_STORAGE_CLEARED", $kind);
            std::println!(
                "BRYNJA_IMPORT_{}_{}",
                $kind,
                if accepted { "ACCEPTED" } else { "REJECTED" }
            );
            Ok(accepted)
        }
    };
}

import_runner!(cached, Cached<'_>, "CACHED");
import_runner!(local, ephemeral::Ephemeral<'_>, "EPHEMERAL");

macro_rules! fixture {
    ($name:ident, $run:ident, $width:literal) => {
        #[test]
        fn $name() -> Result<(), Error> {
            $run($width).map(|_| ())
        }
    };
}

fixture!(native_import_cached_128, cached, 16);
fixture!(native_import_cached_192, cached, 24);
fixture!(native_import_cached_256, cached, 32);
fixture!(native_import_ephemeral_128, local, 16);
fixture!(native_import_ephemeral_192, local, 24);
fixture!(native_import_ephemeral_256, local, 32);

#[cfg(brynja_fault_evidence)]
#[test]
fn source_import_rejections_exercise_the_fixture_cleanup_branch() -> Result<(), Error> {
    use super::super::super::capture::evidence_tests as capture;
    for width in [16usize, 24, 32] {
        for stage in [capture::Stage::AfterFirst, capture::Stage::AfterSecond] {
            for run in [cached, local] {
                let reset = capture::inject_at(stage, capture::Action::Flip(width.wrapping_sub(1)));
                assert!(!run(width)?);
                assert_eq!(capture::hits(), 1);
                drop(reset);
            }
        }
    }
    Ok(())
}
