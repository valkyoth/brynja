//! Observe import and first use separately. Only the external runner decides
//! which outcome is expected for its selected public-fixture experiment.
use super::*;

#[derive(Debug, PartialEq)]
enum Outcome {
    Accepted,
    ImportRejected,
    UseRejectedRetired,
}

#[inline(never)]
fn run(width: usize, public: bool, inverse: bool) -> Result<Outcome, Error> {
    let plain = tests::answer("00112233445566778899aabbccddeeff")?;
    let cipher = tests::answer(match width {
        16 => "69c4e0d86a7b0430d8cdb78070b4c55a",
        24 => "dda97ca4864cdfe06eaf70a0ec0d7191",
        32 => "8ea2b7ca516745bfeafc49904b496089",
        _ => return Err(Error::SecretMemory),
    })?;
    let path = if public {
        "public"
    } else if inverse {
        "decrypt"
    } else {
        "encrypt"
    };
    let input = if inverse { cipher } else { plain };
    let expected = if inverse { plain } else { cipher };
    std::println!(
        "BRYNJA_IMPORT_USE_EVIDENCE_CFG={}",
        cfg!(brynja_fault_evidence)
    );
    std::println!("BRYNJA_IMPORT_USE_CASE={width}:{path}");
    let mut key = [0; 32];
    for (byte, value) in key.iter_mut().zip(0u8..32) {
        *byte = value;
    }
    let original = key;
    let mut primary = [0x91; 34];
    let mut secondary = [0x92; 34];
    let mut output = [0x93; 16];
    let end = width.wrapping_add(1);
    let outcome;
    {
        let imported = ephemeral::Ephemeral::new_profile(
            black_box(key.get(..width).ok_or(Error::SecretMemory)?),
            primary.get_mut(1..end).ok_or(Error::SecretMemory)?,
            secondary.get_mut(1..end).ok_or(Error::SecretMemory)?,
        );
        outcome = match imported {
            Err(error) => {
                assert_eq!(error, ProfileFailure::ImportRejected);
                assert_eq!(output, [0x93; 16]);
                Outcome::ImportRejected
            }
            Ok(mut owner) => {
                std::println!("BRYNJA_IMPORT_USE_OWNER_RETURNED");
                let accepted = if public {
                    match black_box(&mut owner).encrypt_public_profile(
                        &input,
                        &mut output,
                        PublicCiphertext::acknowledge(),
                    ) {
                        Ok(()) => {
                            assert_eq!(output, expected);
                            true
                        }
                        Err(error) => {
                            assert_eq!(error, ProfileFailure::RejectedAndRetired);
                            assert_eq!(output, [0x93; 16]);
                            false
                        }
                    }
                } else {
                    let accepted =
                        match black_box(&mut owner).secret_profile(&input, &mut output, inverse) {
                            Ok(block) => {
                                assert_eq!(block.expose(), &expected);
                                drop(block);
                                true
                            }
                            Err(error) => {
                                assert_eq!(error, ProfileFailure::RejectedAndRetired);
                                false
                            }
                        };
                    assert_eq!(output, [0; 16]);
                    accepted
                };
                if accepted {
                    owner.encrypt_public(&plain, &mut output, PublicCiphertext::acknowledge())?;
                    assert_eq!(output, cipher);
                    Outcome::Accepted
                } else {
                    output.fill(0x93);
                    assert_eq!(
                        owner.encrypt_public_profile(
                            &plain,
                            &mut output,
                            PublicCiphertext::acknowledge()
                        ),
                        Err(ProfileFailure::AlreadyRetired)
                    );
                    assert_eq!(output, [0x93; 16]);
                    for inverse in [false, true] {
                        output.fill(0x93);
                        assert_eq!(
                            owner.secret_profile(&input, &mut output, inverse).err(),
                            Some(ProfileFailure::AlreadyRetired)
                        );
                        assert_eq!(output, [0; 16]);
                    }
                    Outcome::UseRejectedRetired
                }
            }
        };
    }
    assert_eq!(key, original);
    for (storage, sentinel) in [(&primary, 0x91), (&secondary, 0x92)] {
        assert_eq!(storage.first(), Some(&sentinel));
        assert!(
            storage
                .get(1..end)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|v| *v == 0)
        );
        assert!(
            storage
                .get(end..)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|v| *v == sentinel)
        );
    }
    std::println!("BRYNJA_IMPORT_USE_SOURCE_AND_GUARDS_INTACT");
    std::println!("BRYNJA_IMPORT_USE_STORAGE_CLEARED");
    std::println!(
        "BRYNJA_IMPORT_USE_{}",
        match outcome {
            Outcome::Accepted => "ACCEPTED",
            Outcome::ImportRejected => "IMPORT_REJECTED",
            Outcome::UseRejectedRetired => "USE_REJECTED_RETIRED",
        }
    );
    Ok(outcome)
}

macro_rules! fixture {
    ($name:ident, $width:literal, $public:literal, $inverse:literal) => {
        #[test]
        fn $name() -> Result<(), Error> {
            run($width, $public, $inverse).map(|_| ())
        }
    };
}
fixture!(native_import_use_128_public, 16, true, false);
fixture!(native_import_use_192_public, 24, true, false);
fixture!(native_import_use_256_public, 32, true, false);
fixture!(native_import_use_128_encrypt, 16, false, false);
fixture!(native_import_use_192_encrypt, 24, false, false);
fixture!(native_import_use_256_encrypt, 32, false, false);
fixture!(native_import_use_128_decrypt, 16, false, true);
fixture!(native_import_use_192_decrypt, 24, false, true);
fixture!(native_import_use_256_decrypt, 32, false, true);

#[cfg(brynja_fault_evidence)]
#[test]
fn rejected_import_never_becomes_a_use_failure() -> Result<(), Error> {
    use super::super::super::capture::evidence_tests as capture;
    for width in [16usize, 24, 32] {
        for stage in [capture::Stage::AfterFirst, capture::Stage::AfterSecond] {
            for (public, inverse) in [(true, false), (false, false), (false, true)] {
                let reset = capture::inject_at(stage, capture::Action::Flip(width.wrapping_sub(1)));
                assert_eq!(run(width, public, inverse)?, Outcome::ImportRejected);
                assert_eq!(capture::hits(), 1);
                drop(reset);
            }
        }
    }
    Ok(())
}
