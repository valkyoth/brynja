extern crate std;
use super::*;

#[test]
fn borrowed_buffer_updates_preserve_source_and_unused_capacity() -> Result<(), HardenedSha3Error> {
    let mut owner = HardenedFips202Owner::<136>::new();
    let input = [0x12, 0xe7, 0x81, 0x43, 0x9b];
    owner
        .update(&input[..2])
        .map_err(|()| HardenedSha3Error::MessageTooLong)?;
    owner
        .update(&[])
        .map_err(|()| HardenedSha3Error::MessageTooLong)?;
    owner
        .update(&input[2..])
        .map_err(|()| HardenedSha3Error::MessageTooLong)?;
    assert_eq!(
        owner.partial_input.get(..input.len()),
        Some(input.as_slice())
    );
    assert!(
        owner
            .partial_input
            .get(input.len()..)
            .ok_or(HardenedSha3Error::OutputLength)?
            .iter()
            .all(|byte| *byte == 0)
    );
    assert_eq!(owner.buffer_len(), input.len());
    assert_eq!(owner.message_bytes(), input.len() as u128);
    assert_eq!(input, [0x12, 0xe7, 0x81, 0x43, 0x9b]);
    Ok(())
}

#[test]
fn borrowed_fixed_public_commits_preserve_byte_and_bit_digests() -> Result<(), HardenedSha3Error> {
    let input = [0x96, 0x07];
    let mut state = crate::HardenedSha3_256::new();
    state.update(&input)?;
    let mut output = [0xa5; 32];
    state.finalize_public(&mut output, Sha3PublicDeclassification::acknowledge())?;
    assert_eq!(
        &output,
        crate::sha3_256(&input)
            .map_err(|_| HardenedSha3Error::OutputLength)?
            .as_bytes()
    );
    let bits =
        crate::Fips202BitString::new(&input, 3).map_err(|_| HardenedSha3Error::OutputLength)?;
    crate::HardenedSha3_256::new().finalize_bits_public(
        bits,
        &mut output,
        Sha3PublicDeclassification::acknowledge(),
    )?;
    assert_eq!(
        &output,
        crate::sha3_256_bits(bits)
            .map_err(|_| HardenedSha3Error::OutputLength)?
            .as_bytes()
    );
    Ok(())
}

#[test]
fn borrowed_staging_and_invalid_ranges_are_atomic() -> Result<(), HardenedSha3Error> {
    let mut owner = HardenedFips202Owner::<136>::new();
    for (index, byte) in owner.sponge_lanes.iter_mut().enumerate() {
        *byte = u8::try_from(index).map_err(|_| HardenedSha3Error::OutputLength)?;
    }
    for length in [0, 1, 28, 64, 168] {
        owner.squeeze_staging.fill(0xa5);
        owner.stage_fixed(length)?;
        assert_eq!(
            owner.squeeze_staging.get(..length),
            owner.sponge_lanes.get(..length)
        );
        assert!(
            owner
                .squeeze_staging
                .get(length..)
                .ok_or(HardenedSha3Error::OutputLength)?
                .iter()
                .all(|byte| *byte == 0xa5)
        );
    }
    owner.squeeze_staging.fill(0xa5);
    owner.set_squeeze_position(136);
    let original = owner.sponge_lanes;
    assert_eq!(owner.stage_fixed(169), Err(HardenedSha3Error::OutputLength));
    assert_eq!(
        owner.fill_staging(169),
        Err(HardenedSha3Error::OutputLength)
    );
    assert_eq!(owner.squeeze_staging, [0xa5; 168]);
    assert_eq!(owner.sponge_lanes, original);
    assert_eq!(owner.squeeze_position(), 136);
    owner.squeeze_to_slice(&mut [])?;
    assert_eq!(owner.squeeze_position(), 136);
    assert_eq!(owner.sponge_lanes, original);
    for position in [137, 168, 255] {
        owner.set_squeeze_position(position);
        let mut output = [0x5a; 3];
        assert_eq!(
            owner.squeeze_to_slice(&mut output),
            Err(HardenedSha3Error::StateConsumed)
        );
        assert_eq!(output, [0x5a; 3]);
        assert_eq!(owner.fill_staging(1), Err(HardenedSha3Error::StateConsumed));
        assert_eq!(owner.squeeze_staging, [0xa5; 168]);
    }
    Ok(())
}

fn reference<const RATE: usize>(output: &mut [u8]) -> Result<(), HardenedSha3Error> {
    if RATE == 136 {
        let mut reference = crate::Shake256::new();
        reference
            .update(b"borrowed portable sponge")
            .map_err(|_| HardenedSha3Error::MessageTooLong)?;
        reference
            .finalize_xof()
            .squeeze(output)
            .map_err(|_| HardenedSha3Error::OutputTooLong)
    } else {
        let mut reference = crate::Shake128::new();
        reference
            .update(b"borrowed portable sponge")
            .map_err(|_| HardenedSha3Error::MessageTooLong)?;
        reference
            .finalize_xof()
            .squeeze(output)
            .map_err(|_| HardenedSha3Error::OutputTooLong)
    }
}
fn owner<const RATE: usize>() -> Result<HardenedFips202Owner<RATE>, HardenedSha3Error> {
    let mut owner = HardenedFips202Owner::<RATE>::new();
    owner
        .update(b"borrowed portable sponge")
        .map_err(|()| HardenedSha3Error::MessageTooLong)?;
    owner.finalize(None, SHAKE_SUFFIX, SHAKE_SUFFIX_BITS);
    Ok(owner)
}

fn chunks<const RATE: usize>() -> Result<(), HardenedSha3Error> {
    let mut expected = [0; 1024];
    reference::<RATE>(&mut expected)?;
    let mut owner = owner::<RATE>()?;
    let mut offset = 0_usize;
    let before = RATE.checked_sub(1).ok_or(HardenedSha3Error::OutputLength)?;
    let after = RATE.checked_add(1).ok_or(HardenedSha3Error::OutputLength)?;
    let twice = RATE
        .checked_mul(2)
        .and_then(|n| n.checked_add(7))
        .ok_or(HardenedSha3Error::OutputLength)?;
    for (index, length) in [0, 1, before, 0, RATE, after, twice]
        .into_iter()
        .enumerate()
    {
        let capacity = length
            .checked_add(2)
            .ok_or(HardenedSha3Error::OutputLength)?;
        let target_end = length
            .checked_add(1)
            .ok_or(HardenedSha3Error::OutputLength)?;
        let mut output = std::vec![0xa5; capacity];
        let target = output
            .get_mut(1..target_end)
            .ok_or(HardenedSha3Error::OutputLength)?;
        let end = offset
            .checked_add(length)
            .ok_or(HardenedSha3Error::OutputLength)?;
        if length == 0 || index % 2 == 0 {
            owner.squeeze_public(target, Sha3PublicDeclassification::acknowledge())?;
            assert_eq!(Some(&*target), expected.get(offset..end));
        } else {
            let mut initialization = SecretRegionInitialization::begin(target)?;
            owner.squeeze_secret(&mut initialization, length)?;
            let secret = initialization.finish()?;
            assert_eq!(Some(secret.expose()), expected.get(offset..end));
            drop(secret);
            assert!(target.iter().all(|byte| *byte == 0));
        }
        assert_eq!(output.first(), Some(&0xa5));
        assert_eq!(output.last(), Some(&0xa5));
        assert_eq!(owner.output_bytes(), end as u128);
        assert_eq!(
            owner.squeeze_position(),
            if end == 0 {
                0
            } else {
                end.checked_sub(1)
                    .and_then(|n| n.checked_rem(RATE))
                    .and_then(|n| n.checked_add(1))
                    .ok_or(HardenedSha3Error::OutputLength)?
            }
        );
        assert_eq!(owner.squeeze_staging, [0; 168]);
        offset = end;
    }
    Ok(())
}

#[test]
fn borrowed_xof_chunks_preserve_values_counters_and_guards() -> Result<(), HardenedSha3Error> {
    chunks::<136>()?;
    chunks::<168>()
}

fn final_bits<const RATE: usize>() -> Result<(), HardenedSha3Error> {
    let before = RATE.checked_sub(1).ok_or(HardenedSha3Error::OutputLength)?;
    let after = RATE.checked_add(1).ok_or(HardenedSha3Error::OutputLength)?;
    let twice = RATE
        .checked_mul(2)
        .and_then(|n| n.checked_add(1))
        .ok_or(HardenedSha3Error::OutputLength)?;
    for length in [1, before, RATE, after, twice] {
        for valid in 1..=8 {
            let mut expected = std::vec![0; length];
            reference::<RATE>(&mut expected)?;
            *expected.last_mut().ok_or(HardenedSha3Error::OutputLength)? &= low_mask(valid);
            let mut output = std::vec![0xa5; length];
            let mut public_owner = owner::<RATE>()?;
            public_owner.squeeze_final_bits_public(
                Fips202Output::new(&mut output, valid)
                    .map_err(|_| HardenedSha3Error::OutputLength)?,
                Sha3PublicDeclassification::acknowledge(),
            )?;
            assert_eq!(output, expected);
            let mut secret_owner = owner::<RATE>()?;
            let mut initialization = SecretRegionInitialization::begin(&mut output)?;
            secret_owner.squeeze_final_bits_secret(length, valid, &mut initialization)?;
            let secret = initialization.finish()?;
            assert_eq!(secret.expose(), expected);
            assert_eq!(secret_owner.output_bytes(), public_owner.output_bytes());
            assert_eq!(
                secret_owner.squeeze_position(),
                public_owner.squeeze_position()
            );
            assert_eq!(secret_owner.squeeze_staging, [0; 168]);
            drop(secret);
            assert!(output.iter().all(|byte| *byte == 0));
        }
    }
    Ok(())
}

#[test]
fn borrowed_partial_xof_output_matches_and_clears() -> Result<(), HardenedSha3Error> {
    final_bits::<136>()?;
    final_bits::<168>()
}

#[test]
fn borrowed_fixed_domain_byte_operations_are_total() -> Result<(), HardenedSha3Error> {
    for source in 0..=u8::MAX {
        let mut target = [0xa5, 0, 0x69];
        copy_byte(&mut target[1], &source);
        assert_eq!(target, [0xa5, source, 0x69]);
        for initial in 0..=u8::MAX {
            target[1] = initial;
            xor_byte(&mut target[1], &source);
            assert_eq!(target, [0xa5, initial ^ source, 0x69]);
            // The discarded Result in the infallible adapter is always Ok for
            // its fixed public range, irrespective of either byte's value.
            assert_eq!(
                brynja_core::xor_secret_byte_bits(&mut target[1], &source, 0, 8, 0),
                Ok(())
            );
            assert_eq!(target, [0xa5, initial, 0x69]);
        }
    }
    Ok(())
}

#[test]
fn borrowed_input_split_retains_the_original_tail() -> Result<(), HardenedSha3Error> {
    let bytes = [0x96, 0x03];
    let empty =
        crate::Fips202BitString::new(&[], 0).map_err(|_| HardenedSha3Error::OutputLength)?;
    assert_eq!(split_input(empty), (&[][..], None));
    for valid in 2..=8 {
        let input = crate::Fips202BitString::new(&bytes, valid)
            .map_err(|_| HardenedSha3Error::OutputLength)?;
        let (complete, partial) = split_input(input);
        if valid == 8 {
            assert_eq!(complete, bytes);
            assert!(partial.is_none());
        } else {
            assert_eq!(complete, &bytes[..1]);
            let (tail, width) = partial.ok_or(HardenedSha3Error::OutputLength)?;
            assert!(core::ptr::eq(tail, &bytes[1]));
            assert_eq!(width, valid);
        }
    }
    Ok(())
}

fn padding<const RATE: usize>() -> Result<(), HardenedSha3Error> {
    let lengths = [
        0,
        1,
        RATE.checked_sub(2).ok_or(HardenedSha3Error::OutputLength)?,
        RATE.checked_sub(1).ok_or(HardenedSha3Error::OutputLength)?,
        RATE,
        RATE.checked_add(1).ok_or(HardenedSha3Error::OutputLength)?,
        RATE.checked_mul(2)
            .and_then(|n| n.checked_sub(1))
            .ok_or(HardenedSha3Error::OutputLength)?,
        RATE.checked_mul(2)
            .and_then(|n| n.checked_add(3))
            .ok_or(HardenedSha3Error::OutputLength)?,
    ];
    let chunk_sizes = [
        1,
        RATE.checked_sub(1).ok_or(HardenedSha3Error::OutputLength)?,
        RATE.checked_add(3).ok_or(HardenedSha3Error::OutputLength)?,
    ];
    for length in lengths {
        let mut message = std::vec![0; length];
        for (index, byte) in message.iter_mut().enumerate() {
            *byte = u8::try_from(index % 256)
                .map_err(|_| HardenedSha3Error::OutputLength)?
                .wrapping_mul(73)
                .wrapping_add(0x96);
        }
        for valid in 0..8 {
            // Exercise the private mask defensively even with high unused
            // bits set; public bit strings separately require canonical input.
            let tail = 0xff;
            let partial = if valid == 0 {
                None
            } else {
                Some((&tail, valid))
            };
            for (suffix, width) in [
                (SHA3_SUFFIX, SHA3_SUFFIX_BITS),
                (SHAKE_SUFFIX, SHAKE_SUFFIX_BITS),
                (0x04, 3),
            ] {
                let mut reference = crate::sponge::Sponge::<RATE>::new();
                reference
                    .update(&message)
                    .map_err(|()| HardenedSha3Error::MessageTooLong)?;
                let mut reader = reference.finalize_domain_xof(
                    partial.map(|(byte, count)| (*byte, count)),
                    suffix,
                    width,
                );
                let output_len = RATE
                    .checked_mul(2)
                    .and_then(|n| n.checked_add(11))
                    .ok_or(HardenedSha3Error::OutputLength)?;
                let mut expected = std::vec![0; output_len];
                reader
                    .squeeze(&mut expected)
                    .map_err(|()| HardenedSha3Error::OutputTooLong)?;
                for chunk in chunk_sizes {
                    let mut owner = HardenedFips202Owner::<RATE>::new();
                    for bytes in message.chunks(chunk) {
                        owner
                            .update(bytes)
                            .map_err(|()| HardenedSha3Error::MessageTooLong)?;
                    }
                    owner.finalize(partial, suffix, width);
                    assert_eq!(owner.partial_input, [0; 168]);
                    assert_eq!(owner.padding_block, [0; 168]);
                    assert_eq!(owner.suffix_staging, [0; 4]);
                    assert_eq!(owner.message_bytes(), length as u128);
                    let mut actual = std::vec![0xa5; output_len];
                    owner.squeeze_public(&mut actual, Sha3PublicDeclassification::acknowledge())?;
                    assert_eq!(
                        actual, expected,
                        "rate={RATE} length={length} valid={valid} suffix={suffix} chunk={chunk}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn borrowed_absorption_padding_matches_every_rate_and_suffix() -> Result<(), HardenedSha3Error> {
    padding::<72>()?;
    padding::<104>()?;
    padding::<136>()?;
    padding::<144>()?;
    padding::<168>()
}

#[test]
fn borrowed_padding_crosses_rate_without_retaining_tail() -> Result<(), HardenedSha3Error> {
    let message = [0x96; 135];
    let tail = 0x7f;
    let mut owner = HardenedFips202Owner::<136>::new();
    owner
        .update(&message)
        .map_err(|()| HardenedSha3Error::MessageTooLong)?;
    owner.finalize(Some((&tail, 7)), SHAKE_SUFFIX, SHAKE_SUFFIX_BITS);
    let mut actual = [0xa5; 32];
    owner.squeeze_public(&mut actual, Sha3PublicDeclassification::acknowledge())?;
    let mut reference = crate::sponge::Sponge::<136>::new();
    reference
        .update(&message)
        .map_err(|()| HardenedSha3Error::MessageTooLong)?;
    let mut expected = [0; 32];
    reference
        .finalize_bits_xof(Some((tail, 7)))
        .squeeze(&mut expected)
        .map_err(|()| HardenedSha3Error::OutputTooLong)?;
    assert_eq!(actual, expected);
    assert_eq!(tail, 0x7f);
    assert_eq!(owner.partial_input, [0; 168]);
    assert_eq!(owner.padding_block, [0; 168]);
    assert_eq!(owner.suffix_staging, [0; 4]);
    Ok(())
}
