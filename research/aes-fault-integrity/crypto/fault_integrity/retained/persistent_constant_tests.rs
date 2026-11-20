use super::super::corruption_tests::PersistentCoefficientFault;
use super::*;

#[cfg(brynja_fault_evidence)]
type FilteredInputs = ([u8; 16], [u8; 16], [u8; 16]);

#[cfg(brynja_fault_evidence)]
fn filtered_constant_inputs(key: &[u8], inverse: bool) -> Result<FilteredInputs, Error> {
    let mut primary = Primary::new(key.len())?;
    primary.expand(key)?;
    let mut secondary = Schedule::new();
    secondary.expand(key)?;
    let fault = PersistentCoefficientFault::install_transform_high();
    let mut unaffected = None;
    let mut affected = None;
    for value in 0..=u8::MAX {
        let mut input = [0x42; 16];
        input[0] = value;
        let mut correct = input;
        primary.transform(&mut correct, inverse)?;
        let mut observed = [0; 16];
        secondary.transform(&input, &mut observed, inverse)?;
        let (calls, effective) = fault.take_counts();
        assert!(calls > 0);
        if observed == correct && effective == 0 {
            unaffected.get_or_insert((input, correct));
        } else if observed != correct && effective > 0 {
            affected.get_or_insert(input);
        }
        if let (Some((safe, expected)), Some(faulted)) = (unaffected, affected) {
            return Ok((safe, faulted, expected));
        }
    }
    Err(Error::SecretMemory)
}

#[cfg(brynja_fault_evidence)]
trait TestOwner {
    fn encrypt_public(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<(), ProfileFailure>;
    fn secret<'out>(
        &mut self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
        inverse: bool,
    ) -> Result<SecretBlock<'out>, ProfileFailure>;
}

#[cfg(brynja_fault_evidence)]
impl TestOwner for Cached<'_> {
    fn encrypt_public(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<(), ProfileFailure> {
        self.encrypt_public_profile(input, output, PublicCiphertext::acknowledge())
    }

    fn secret<'out>(
        &mut self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
        inverse: bool,
    ) -> Result<SecretBlock<'out>, ProfileFailure> {
        self.secret_profile(input, output, inverse)
    }
}

#[cfg(brynja_fault_evidence)]
impl TestOwner for ephemeral::Ephemeral<'_> {
    fn encrypt_public(
        &mut self,
        input: &[u8; 16],
        output: &mut [u8; 16],
    ) -> Result<(), ProfileFailure> {
        self.encrypt_public_profile(input, output, PublicCiphertext::acknowledge())
    }

    fn secret<'out>(
        &mut self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
        inverse: bool,
    ) -> Result<SecretBlock<'out>, ProfileFailure> {
        self.secret_profile(input, output, inverse)
    }
}

#[cfg(brynja_fault_evidence)]
fn exercise_persistent_fault(
    owner: &mut impl TestOwner,
    public: bool,
    inverse: bool,
    safe: &[u8; 16],
    faulted: &[u8; 16],
    expected: &[u8; 16],
    output: &mut [u8; 16],
) -> Result<(), Error> {
    let fault = PersistentCoefficientFault::install_transform_high();
    if public {
        owner.encrypt_public(safe, output)?;
        assert_eq!(output, expected);
        let (calls, effective) = fault.take_counts();
        assert!(calls > 0);
        assert_eq!(effective, 0);
        output.fill(0x93);
        assert_eq!(
            owner.encrypt_public(faulted, output),
            Err(ProfileFailure::RejectedAndRetired)
        );
        assert_eq!(output, &[0x93; 16]);
    } else {
        let block = owner.secret(safe, output, inverse)?;
        assert_eq!(block.expose(), expected);
        drop(block);
        assert_eq!(output, &[0; 16]);
        let (calls, effective) = fault.take_counts();
        assert!(calls > 0);
        assert_eq!(effective, 0);
        output.fill(0x93);
        assert_eq!(
            owner.secret(faulted, output, inverse).err(),
            Some(ProfileFailure::RejectedAndRetired)
        );
        assert_eq!(output, &[0; 16]);
    }
    let (calls, effective) = fault.take_counts();
    assert!(calls > 0 && effective > 0);
    output.fill(0x93);
    assert_eq!(
        owner.encrypt_public(safe, output),
        Err(ProfileFailure::AlreadyRetired)
    );
    assert_eq!(output, &[0x93; 16]);
    assert_eq!(
        owner.secret(safe, output, true).err(),
        Some(ProfileFailure::AlreadyRetired)
    );
    assert_eq!(output, &[0; 16]);
    assert_eq!(fault.take_counts(), (0, 0));
    Ok(())
}

#[cfg(brynja_fault_evidence)]
#[test]
fn persistent_secondary_constant_filters_correct_blocks_then_retires() -> Result<(), Error> {
    let mut key = [0; 32];
    for (byte, value) in key.iter_mut().zip(0u8..32) {
        *byte = value;
    }
    for width in [16, 24, 32] {
        for (public, inverse) in [(true, false), (false, false), (false, true)] {
            let raw = key.get(..width).ok_or(Error::SecretMemory)?;
            let (safe, faulted, expected) = filtered_constant_inputs(raw, inverse)?;
            for operation_local in [false, true] {
                let mut primary = [0x91; 32];
                let mut secondary = [0x92; 32];
                let mut output = [0x93; 16];
                {
                    let primary_storage = primary.get_mut(..width).ok_or(Error::SecretMemory)?;
                    let secondary_storage =
                        secondary.get_mut(..width).ok_or(Error::SecretMemory)?;
                    if operation_local {
                        let mut owner =
                            ephemeral::Ephemeral::new(raw, primary_storage, secondary_storage)?;
                        exercise_persistent_fault(
                            &mut owner,
                            public,
                            inverse,
                            &safe,
                            &faulted,
                            &expected,
                            &mut output,
                        )?;
                    } else {
                        let mut owner = Cached::new(raw, primary_storage, secondary_storage)?;
                        exercise_persistent_fault(
                            &mut owner,
                            public,
                            inverse,
                            &safe,
                            &faulted,
                            &expected,
                            &mut output,
                        )?;
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
                assert!(
                    primary
                        .get(width..)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|byte| *byte == 0x91)
                );
                assert!(
                    secondary
                        .get(width..)
                        .ok_or(Error::SecretMemory)?
                        .iter()
                        .all(|byte| *byte == 0x92)
                );
            }
        }
    }
    Ok(())
}

#[cfg(brynja_fault_evidence)]
#[test]
fn persistent_expansion_constant_rejects_cached_import_and_clears_storage() -> Result<(), Error> {
    let mut key = [0; 32];
    for (byte, value) in key.iter_mut().zip(0u8..32) {
        *byte = value;
    }
    for width in [16, 24, 32] {
        let mut primary = [0x91; 32];
        let mut secondary = [0x92; 32];
        {
            let fault = PersistentCoefficientFault::install_expansion_affine();
            assert!(matches!(
                Cached::new_profile(
                    key.get(..width).ok_or(Error::SecretMemory)?,
                    primary.get_mut(..width).ok_or(Error::SecretMemory)?,
                    secondary.get_mut(..width).ok_or(Error::SecretMemory)?,
                ),
                Err(ProfileFailure::ImportRejected)
            ));
            let (calls, effective) = fault.take_counts();
            assert!(calls > 0 && effective > 0);
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
        assert!(
            primary
                .get(width..)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|byte| *byte == 0x91)
        );
        assert!(
            secondary
                .get(width..)
                .ok_or(Error::SecretMemory)?
                .iter()
                .all(|byte| *byte == 0x92)
        );
    }
    Ok(())
}

#[cfg(brynja_fault_evidence)]
#[test]
fn persistent_expansion_constant_retires_operation_local_owner() -> Result<(), Error> {
    let mut key = [0; 32];
    for (byte, value) in key.iter_mut().zip(0u8..32) {
        *byte = value;
    }
    let input = [0x42; 16];
    for width in [16, 24, 32] {
        for (public, inverse) in [(true, false), (false, false), (false, true)] {
            let mut primary = [0x91; 32];
            let mut secondary = [0x92; 32];
            let mut output = [0x93; 16];
            {
                let mut owner = ephemeral::Ephemeral::new(
                    key.get(..width).ok_or(Error::SecretMemory)?,
                    primary.get_mut(..width).ok_or(Error::SecretMemory)?,
                    secondary.get_mut(..width).ok_or(Error::SecretMemory)?,
                )?;
                let fault = PersistentCoefficientFault::install_expansion_affine();
                if public {
                    assert_eq!(
                        owner.encrypt_public_profile(
                            &input,
                            &mut output,
                            PublicCiphertext::acknowledge(),
                        ),
                        Err(ProfileFailure::RejectedAndRetired)
                    );
                    assert_eq!(output, [0x93; 16]);
                } else {
                    assert_eq!(
                        owner.secret_profile(&input, &mut output, inverse).err(),
                        Some(ProfileFailure::RejectedAndRetired)
                    );
                    assert_eq!(output, [0; 16]);
                }
                let (calls, effective) = fault.take_counts();
                assert!(calls > 0 && effective > 0);
                output.fill(0x93);
                assert_eq!(
                    owner.encrypt_public_profile(
                        &input,
                        &mut output,
                        PublicCiphertext::acknowledge(),
                    ),
                    Err(ProfileFailure::AlreadyRetired)
                );
                assert_eq!(output, [0x93; 16]);
                assert_eq!(
                    owner.secret_profile(&input, &mut output, true).err(),
                    Some(ProfileFailure::AlreadyRetired)
                );
                assert_eq!(output, [0; 16]);
                assert_eq!(fault.take_counts(), (0, 0));
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
            assert!(
                primary
                    .get(width..)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|byte| *byte == 0x91)
            );
            assert!(
                secondary
                    .get(width..)
                    .ok_or(Error::SecretMemory)?
                    .iter()
                    .all(|byte| *byte == 0x92)
            );
        }
    }
    Ok(())
}
