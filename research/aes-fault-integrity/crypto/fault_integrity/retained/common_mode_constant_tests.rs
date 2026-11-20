//! Deliberately escaping two-domain constant fault; outside the one-domain model.
use super::*;
use crate::aes::{fault_integrity::corruption_tests::PersistentCoefficientFault, portable};

trait EncryptOwner {
    fn public(&mut self, input: &[u8; 16], output: &mut [u8; 16]) -> Result<(), ProfileFailure>;
    fn secret<'out>(
        &mut self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
    ) -> Result<SecretBlock<'out>, ProfileFailure>;
}

impl EncryptOwner for Cached<'_> {
    fn public(&mut self, input: &[u8; 16], output: &mut [u8; 16]) -> Result<(), ProfileFailure> {
        self.encrypt_public_profile(input, output, PublicCiphertext::acknowledge())
    }

    fn secret<'out>(
        &mut self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
    ) -> Result<SecretBlock<'out>, ProfileFailure> {
        self.secret_profile(input, output, false)
    }
}

impl EncryptOwner for ephemeral::Ephemeral<'_> {
    fn public(&mut self, input: &[u8; 16], output: &mut [u8; 16]) -> Result<(), ProfileFailure> {
        self.encrypt_public_profile(input, output, PublicCiphertext::acknowledge())
    }

    fn secret<'out>(
        &mut self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
    ) -> Result<SecretBlock<'out>, ProfileFailure> {
        self.secret_profile(input, output, false)
    }
}

fn exercise_agreeing_wrong_output(
    owner: &mut impl EncryptOwner,
    input: &[u8; 16],
    expected: &[u8; 16],
) -> Result<(), Error> {
    let primary_fault = portable::field_fault_fixture::PersistentFault::transform(false);
    let secondary_fault = PersistentCoefficientFault::install_transform_affine();
    let mut output = [0x93; 16];
    owner.public(input, &mut output).map_err(Error::from)?;
    let wrong = output;
    assert_ne!(&wrong, expected);
    let secret = owner.secret(input, &mut output).map_err(Error::from)?;
    assert_eq!(secret.expose(), &wrong);
    drop(secret);
    assert_eq!(output, [0; 16]);
    assert!(primary_fault.take_calls() > 0);
    let (calls, effective) = secondary_fault.take_counts();
    assert!(calls > 0 && effective > 0);
    drop(primary_fault);
    drop(secondary_fault);
    owner.public(input, &mut output).map_err(Error::from)?;
    assert_eq!(&output, expected);
    Ok(())
}

fn exercise_secondary_only(owner: &mut impl EncryptOwner, input: &[u8; 16]) {
    let fault = PersistentCoefficientFault::install_transform_affine();
    let mut output = [0x93; 16];
    assert_eq!(
        owner.public(input, &mut output),
        Err(ProfileFailure::RejectedAndRetired)
    );
    assert_eq!(output, [0x93; 16]);
    let (calls, effective) = fault.take_counts();
    assert!(calls > 0 && effective > 0);
    assert_eq!(
        owner.public(input, &mut output),
        Err(ProfileFailure::AlreadyRetired)
    );
    assert_eq!(output, [0x93; 16]);
    assert_eq!(fault.take_counts(), (0, 0));
}

#[test]
fn correlated_affine_fault_can_release_wrong_blocks_without_retirement() -> Result<(), Error> {
    let input = super::tests::answer("00112233445566778899aabbccddeeff")?;
    for (width, expected) in [
        (16, "69c4e0d86a7b0430d8cdb78070b4c55a"),
        (24, "dda97ca4864cdfe06eaf70a0ec0d7191"),
        (32, "8ea2b7ca516745bfeafc49904b496089"),
    ] {
        let expected = super::tests::answer(expected)?;
        let mut key = [0; 32];
        for (byte, value) in key.iter_mut().zip(0u8..32) {
            *byte = value;
        }
        let raw = key.get(..width).ok_or(Error::SecretMemory)?;
        for operation_local in [false, true] {
            let mut primary = [0x91; 32];
            let mut secondary = [0x92; 32];
            {
                let first = primary.get_mut(..width).ok_or(Error::SecretMemory)?;
                let second = secondary.get_mut(..width).ok_or(Error::SecretMemory)?;
                if operation_local {
                    let mut owner = ephemeral::Ephemeral::new_profile(raw, first, second)?;
                    exercise_agreeing_wrong_output(&mut owner, &input, &expected)?;
                } else {
                    let mut owner = Cached::new_profile(raw, first, second)?;
                    exercise_agreeing_wrong_output(&mut owner, &input, &expected)?;
                }
            }
            assert!(
                primary
                    .get(..width)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|byte| *byte == 0)
            );
            assert!(
                secondary
                    .get(..width)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
    }
    Ok(())
}

#[test]
fn secondary_affine_fault_alone_is_detected() -> Result<(), Error> {
    let input = super::tests::answer("00112233445566778899aabbccddeeff")?;
    let mut key = [0; 32];
    for (byte, value) in key.iter_mut().zip(0u8..32) {
        *byte = value;
    }
    for width in [16, 24, 32] {
        let raw = key.get(..width).ok_or(Error::SecretMemory)?;
        for operation_local in [false, true] {
            let mut primary = [0x91; 32];
            let mut secondary = [0x92; 32];
            {
                let first = primary.get_mut(..width).ok_or(Error::SecretMemory)?;
                let second = secondary.get_mut(..width).ok_or(Error::SecretMemory)?;
                if operation_local {
                    let mut owner = ephemeral::Ephemeral::new_profile(raw, first, second)?;
                    exercise_secondary_only(&mut owner, &input);
                } else {
                    let mut owner = Cached::new_profile(raw, first, second)?;
                    exercise_secondary_only(&mut owner, &input);
                }
            }
            assert!(
                primary
                    .get(..width)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|byte| *byte == 0)
            );
            assert!(
                secondary
                    .get(..width)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
    }
    Ok(())
}
