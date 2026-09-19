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

#[test]
fn borrowed_staging_matches_independently_packed_cshake() -> Result<(), Error> {
    for wide in [false, true] {
        for used in 0..8 {
            for valid in 1..=8 {
                for length in [0, 1, 167, 168, 169, 336, 337] {
                    let mut input = [0_u8; 337];
                    for (n, byte) in input.iter_mut().enumerate() {
                        *byte = n.to_le_bytes()[0];
                    }
                    let input = input.get(..length).ok_or(Error::SecretMemory)?;
                    let mut reference = [0_u8; 341];
                    let mut count = 0_usize;
                    for (byte, width) in core::iter::once((0xa5, used))
                        .chain(input.iter().map(|byte| (*byte, 8)))
                        .chain(core::iter::once((0x96, valid)))
                        .chain([(0, 8), (1, 8)])
                    // right_encode(0) for XOF
                    {
                        for position in 0..width {
                            *reference.get_mut(count / 8).ok_or(Error::SecretMemory)? |=
                                ((byte >> position) & 1) << (count % 8);
                            count += 1;
                        }
                    }
                    let valid_output = if count.is_multiple_of(8) {
                        8
                    } else {
                        u8::try_from(count % 8).map_err(|_| Error::SecretMemory)?
                    };
                    let packed = Fips202BitString::new(
                        reference
                            .get(..count.div_ceil(8))
                            .ok_or(Error::SecretMemory)?,
                        valid_output,
                    )
                    .map_err(|_| Error::InvalidBitString)?;
                    let mut expected = [0; 32];
                    let output = crate::Fips202Output::new(&mut expected, 8)
                        .map_err(|_| Error::InvalidBitString)?;
                    let name = super::super::bits(b"TupleHash")?;
                    let custom = super::super::bits(b"")?;
                    if wide {
                        brynja_hash_sha3::cshake256_bits(packed, name, custom, output)
                            .map_err(|_| Error::SecretMemory)?;
                    } else {
                        brynja_hash_sha3::cshake128_bits(packed, name, custom, output)
                            .map_err(|_| Error::SecretMemory)?;
                    }
                    let mut core = Core::new(Mode::Portable, wide, custom)?;
                    core.append_bits(&0xa5, used)?;
                    core.append(input)?;
                    core.append_bits(&0x96, valid)?;
                    assert_eq!(core.metadata.staging, [0; 168]);
                    core.finish(0)?;
                    let mut actual = [0xa5; 32];
                    let secret = core.state.secret(&mut actual, 8, false)?;
                    assert_eq!(secret.expose(), expected);
                    drop(secret);
                    assert_eq!(actual, [0; 32]);
                    core.cancel();
                    cleared(&core);
                    let strength = if wide {
                        crate::backend::BackendStrength::Bits256
                    } else {
                        crate::backend::BackendStrength::Bits128
                    };
                    let mut portable = crate::core_state::TupleCore::new(strength, custom)?;
                    if used != 0 {
                        let first = [0xa5 & (u8::MAX >> (8 - used))];
                        portable.push_bit_string(
                            Fips202BitString::new(&first, used)
                                .map_err(|_| Error::InvalidBitString)?,
                        )?;
                    }
                    portable.push_bytes(input)?;
                    let last = [0x96 & (u8::MAX >> (8 - valid))];
                    portable.push_bit_string(
                        Fips202BitString::new(&last, valid).map_err(|_| Error::InvalidBitString)?,
                    )?;
                    let mut reader = portable.finish_in_place(0)?;
                    let secret = reader.squeeze_secret(&mut actual)?;
                    assert_eq!(secret.expose(), expected);
                    drop(secret);
                    assert_eq!(actual, [0; 32]);
                }
            }
        }
    }
    Ok(())
}
