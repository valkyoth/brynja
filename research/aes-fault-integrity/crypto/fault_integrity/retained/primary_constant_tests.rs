//! Source-only primary affine-constant fault model, not emitted-code evidence.
use super::*;
use crate::aes::portable::field_fault_fixture::PersistentFault;

type FilteredInputs = ([u8; 16], [u8; 16], [u8; 16]);

trait TestOwner {
    fn public(&mut self, input: &[u8; 16], output: &mut [u8; 16]) -> Result<(), ProfileFailure>;
    fn secret<'out>(
        &mut self,
        input: &[u8; 16],
        output: &'out mut [u8; 16],
        inverse: bool,
    ) -> Result<SecretBlock<'out>, ProfileFailure>;
}

impl TestOwner for Cached<'_> {
    fn public(&mut self, input: &[u8; 16], output: &mut [u8; 16]) -> Result<(), ProfileFailure> {
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

impl TestOwner for ephemeral::Ephemeral<'_> {
    fn public(&mut self, input: &[u8; 16], output: &mut [u8; 16]) -> Result<(), ProfileFailure> {
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

fn check_transform_fault(
    owner: &mut impl TestOwner,
    input: &[u8; 16],
    output: &mut [u8; 16],
    public: bool,
    inverse: bool,
) {
    let fault = PersistentFault::transform(inverse);
    if public {
        assert_eq!(
            owner.public(input, output),
            Err(ProfileFailure::RejectedAndRetired)
        );
        assert_eq!(output, &[0x93; 16]);
    } else {
        assert_eq!(
            owner.secret(input, output, inverse).err(),
            Some(ProfileFailure::RejectedAndRetired)
        );
        assert_eq!(output, &[0; 16]);
    }
    assert!(fault.take_calls() > 0);
    output.fill(0x93);
    assert_eq!(
        owner.public(input, output),
        Err(ProfileFailure::AlreadyRetired)
    );
    assert_eq!(output, &[0x93; 16]);
    assert_eq!(
        owner.secret(input, output, true).err(),
        Some(ProfileFailure::AlreadyRetired)
    );
    assert_eq!(output, &[0; 16]);
    assert_eq!(fault.take_calls(), 0);
}

#[test]
fn persistent_primary_transform_constant_retires_both_owner_lifetimes() -> Result<(), Error> {
    let key = [0x42; 32];
    let input = [0x24; 16];
    for width in [16, 24, 32] {
        for (public, inverse) in [(true, false), (false, false), (false, true)] {
            for operation_local in [false, true] {
                let mut primary = [0x91; 32];
                let mut secondary = [0x92; 32];
                let mut output = [0x93; 16];
                {
                    let raw = key.get(..width).ok_or(Error::SecretMemory)?;
                    let first = primary.get_mut(..width).ok_or(Error::SecretMemory)?;
                    let second = secondary.get_mut(..width).ok_or(Error::SecretMemory)?;
                    if operation_local {
                        let mut owner = ephemeral::Ephemeral::new_profile(raw, first, second)?;
                        check_transform_fault(&mut owner, &input, &mut output, public, inverse);
                    } else {
                        let mut owner = Cached::new_profile(raw, first, second)?;
                        check_transform_fault(&mut owner, &input, &mut output, public, inverse);
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

#[test]
fn persistent_primary_expansion_constant_rejects_import_or_first_use() -> Result<(), Error> {
    let key = [0x42; 32];
    let input = [0x24; 16];
    for width in [16, 24, 32] {
        let raw = key.get(..width).ok_or(Error::SecretMemory)?;
        let mut primary = [0x91; 32];
        let mut secondary = [0x92; 32];
        {
            let fault = PersistentFault::expansion();
            assert!(matches!(
                Cached::new_profile(
                    raw,
                    primary.get_mut(..width).ok_or(Error::SecretMemory)?,
                    secondary.get_mut(..width).ok_or(Error::SecretMemory)?,
                ),
                Err(ProfileFailure::ImportRejected)
            ));
            assert!(fault.take_calls() > 0);
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

        let mut primary = [0x91; 32];
        let mut secondary = [0x92; 32];
        let mut output = [0x93; 16];
        {
            let mut owner = ephemeral::Ephemeral::new_profile(
                raw,
                primary.get_mut(..width).ok_or(Error::SecretMemory)?,
                secondary.get_mut(..width).ok_or(Error::SecretMemory)?,
            )?;
            let fault = PersistentFault::expansion();
            assert_eq!(
                owner.encrypt_public_profile(&input, &mut output, PublicCiphertext::acknowledge()),
                Err(ProfileFailure::RejectedAndRetired)
            );
            assert_eq!(output, [0x93; 16]);
            assert!(fault.take_calls() > 0);
            assert_eq!(
                owner.secret_profile(&input, &mut output, true).err(),
                Some(ProfileFailure::AlreadyRetired)
            );
            assert_eq!(output, [0; 16]);
            assert_eq!(fault.take_calls(), 0);
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
    Ok(())
}

fn filtered_reduction_inputs(key: &[u8], inverse: bool) -> Result<FilteredInputs, Error> {
    let mut primary = Primary::new(key.len())?;
    primary.expand(key)?;
    let mut secondary = Schedule::new();
    secondary.expand(key)?;
    let fault = PersistentFault::first_reduction();
    let mut unaffected = None;
    let mut affected = None;
    for value in 0..=u8::MAX {
        let mut input = [0x24; 16];
        input[0] = value;
        let mut observed = input;
        primary.transform(&mut observed, inverse)?;
        let (calls, effective) = fault.take_counts();
        assert_eq!(calls, 1);
        let mut correct = [0; 16];
        secondary.transform(&input, &mut correct, inverse)?;
        if effective == 0 && observed == correct {
            unaffected.get_or_insert((input, correct));
        } else if effective == 1 && observed != correct {
            affected.get_or_insert(input);
        }
        if let (Some((safe, expected)), Some(faulted)) = (unaffected, affected) {
            return Ok((safe, faulted, expected));
        }
    }
    Err(Error::SecretMemory)
}

fn check_filtered_reduction(
    owner: &mut impl TestOwner,
    safe: &[u8; 16],
    faulted: &[u8; 16],
    expected: &[u8; 16],
    output: &mut [u8; 16],
    public: bool,
    inverse: bool,
) -> Result<(), Error> {
    let fault = PersistentFault::first_reduction();
    if public {
        assert_eq!(owner.public(safe, output), Ok(()));
        assert_eq!(output, expected);
    } else {
        let block = owner.secret(safe, output, inverse).map_err(Error::from)?;
        assert_eq!(block.expose(), expected);
        drop(block);
        assert_eq!(output, &[0; 16]);
    }
    assert_eq!(fault.take_counts(), (1, 0));
    output.fill(0x93);
    if public {
        assert_eq!(
            owner.public(faulted, output),
            Err(ProfileFailure::RejectedAndRetired)
        );
        assert_eq!(output, &[0x93; 16]);
    } else {
        assert_eq!(
            owner.secret(faulted, output, inverse).err(),
            Some(ProfileFailure::RejectedAndRetired)
        );
        assert_eq!(output, &[0; 16]);
    }
    assert_eq!(fault.take_counts(), (1, 1));
    output.fill(0x93);
    assert_eq!(
        owner.public(safe, output),
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

#[test]
fn persistent_primary_reduction_filters_correct_blocks_then_retires() -> Result<(), Error> {
    let key = [0x42; 32];
    for width in [16, 24, 32] {
        let raw = key.get(..width).ok_or(Error::SecretMemory)?;
        for (public, inverse) in [(true, false), (false, false), (false, true)] {
            let (safe, faulted, expected) = filtered_reduction_inputs(raw, inverse)?;
            for operation_local in [false, true] {
                let mut primary = [0x91; 32];
                let mut secondary = [0x92; 32];
                let mut output = [0x93; 16];
                {
                    let first = primary.get_mut(..width).ok_or(Error::SecretMemory)?;
                    let second = secondary.get_mut(..width).ok_or(Error::SecretMemory)?;
                    if operation_local {
                        let mut owner = ephemeral::Ephemeral::new_profile(raw, first, second)?;
                        check_filtered_reduction(
                            &mut owner,
                            &safe,
                            &faulted,
                            &expected,
                            &mut output,
                            public,
                            inverse,
                        )?;
                    } else {
                        let mut owner = Cached::new_profile(raw, first, second)?;
                        check_filtered_reduction(
                            &mut owner,
                            &safe,
                            &faulted,
                            &expected,
                            &mut output,
                            public,
                            inverse,
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
            }
        }
    }
    Ok(())
}
