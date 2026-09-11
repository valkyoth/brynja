use super::*;

fn cleared(core: &Core<'_>) {
    assert_eq!(core.metadata.pending, [0]);
    assert_eq!(core.metadata.used, [0]);
    assert_eq!(core.metadata.items, [0; 16]);
    assert_eq!(core.metadata.remaining, [0; 16]);
    assert_eq!(core.metadata.input_bits, [0; 16]);
    assert_eq!(core.metadata.output_bits, [0; 16]);
    assert_eq!(core.metadata.phase, [0]);
    assert_eq!(core.metadata.staging, [0; 168]);
}

#[test]
fn metadata_cleanup_covers_every_owned_region() -> Result<(), Error> {
    let mut core = Core::new(Mode::Portable, false, super::super::bits(b"secret")?)?;
    core.metadata.pending.fill(0xa5);
    core.metadata.used.fill(0xa5);
    core.metadata.items.fill(0xa5);
    core.metadata.remaining.fill(0xa5);
    core.metadata.input_bits.fill(0xa5);
    core.metadata.output_bits.fill(0xa5);
    core.metadata.phase.fill(0xa5);
    core.metadata.staging.fill(0xa5);
    core.cancel();
    cleared(&core);
    Ok(())
}

#[test]
fn begin_preflights_the_complete_item_but_commits_only_its_prefix() -> Result<(), Error> {
    for wide in [false, true] {
        // left_encode(8) occupies 16 bits. The prefix fits in both cases,
        // but the complete eight-bit item only fits at the exact boundary.
        for overflow in [false, true] {
            let mut core = Core::new(Mode::Portable, wide, super::super::bits(b"")?)?;
            let initial = u128::MAX - 24 + u128::from(overflow);
            core.metadata.input_bits = initial.to_le_bytes();
            if overflow {
                assert_eq!(core.begin(8), Err(Error::MessageTooLong));
                cleared(&core);
                assert_eq!(core.begin(0), Err(Error::StateConsumed));
            } else {
                core.begin(8)?;
                assert_eq!(core.input_bits(), initial + 16);
                assert_eq!(core.remaining_bits(), 8);
                assert_eq!(core.item_count(), 0);
                core.fragment(super::super::bits(b"x")?)?;
                assert_eq!(core.input_bits(), u128::MAX);
                assert_eq!(core.remaining_bits(), 0);
                assert_eq!(core.item_count(), 0);
                core.complete()?;
                assert_eq!(core.item_count(), 1);
                core.cancel();
                cleared(&core);
            }
        }
    }
    Ok(())
}

#[test]
fn overflow_and_incomplete_operations_erase_metadata() -> Result<(), Error> {
    for case in 0..4 {
        let mut core = Core::new(Mode::Portable, false, super::super::bits(b"")?)?;
        match case {
            0 => {
                core.metadata.input_bits = u128::MAX.to_le_bytes();
                assert_eq!(core.begin(0), Err(Error::MessageTooLong));
            }
            1 => {
                core.metadata.items = u128::MAX.to_le_bytes();
                assert_eq!(core.begin(0), Err(Error::MessageTooLong));
            }
            2 => {
                core.begin(9)?;
                core.fragment(super::super::bits(b"x")?)?;
                assert_eq!(core.complete(), Err(Error::IncompleteItem));
            }
            _ => {
                core.begin(0)?;
                assert_eq!(
                    core.fragment(super::super::bits(b"x")?),
                    Err(Error::MessageTooLong)
                );
            }
        }
        cleared(&core);
        assert_eq!(core.begin(0), Err(Error::StateConsumed));
    }
    Ok(())
}

#[test]
fn output_overflow_clears_secrets_but_preserves_public_destination() -> Result<(), Error> {
    for secret in [false, true] {
        let mut core = Core::new(Mode::Portable, true, super::super::bits(b"")?)?;
        core.finish(0)?;
        core.metadata.output_bits = u128::MAX.to_le_bytes();
        let mut output = [0xa5; 8];
        let mut scratch = [0x5a; 16];
        if secret {
            assert!(matches!(
                core.secret(&mut output, 8, false),
                Err(Error::OutputTooLong)
            ));
            assert_eq!(output, [0; 8]);
        } else {
            assert_eq!(
                core.public(&mut output, 8, &mut scratch, false),
                Err(Error::OutputTooLong)
            );
            assert_eq!(output, [0xa5; 8]);
            assert_eq!(scratch, [0; 16]);
        }
        cleared(&core);
    }
    Ok(())
}

#[test]
fn operation_guard_clears_on_early_return() -> Result<(), Error> {
    let mut core = Core::new(Mode::Portable, false, super::super::bits(b"")?)?;
    core.begin(16)?;
    core.fragment(super::super::bits(b"s")?)?;
    {
        let _operation = Operation::new(&mut core);
    }
    cleared(&core);
    Ok(())
}
