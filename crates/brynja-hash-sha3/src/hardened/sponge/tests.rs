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
