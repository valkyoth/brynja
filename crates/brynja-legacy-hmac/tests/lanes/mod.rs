//! Distinct per-lane data: equal lengths must not hide swapped SIMD lanes.
use super::{BitString, Error, Input, Md5BatchControl, Md5Executor, select};

fn pattern(length: usize, identity: usize, salt: usize) -> Result<Vec<u8>, Error> {
    let identity = u8::try_from(identity).map_err(|_| Error::SecretMemory)?;
    let salt = u8::try_from(salt).map_err(|_| Error::SecretMemory)?;
    (0..length)
        .map(|index| {
            // The test pattern is explicitly defined modulo 256.
            Ok(u8::try_from(index % 256)
                .map_err(|_| Error::SecretMemory)?
                .wrapping_mul(29)
                .wrapping_add(identity.wrapping_mul(37))
                .wrapping_add(salt.wrapping_mul(11))
                .wrapping_add(1))
        })
        .collect()
}

fn rotate(lane: usize, offset: usize) -> Result<usize, Error> {
    lane.checked_add(offset)
        .map(|n| n % 8)
        .ok_or(Error::SecretMemory)
}

fn key_size(shape: usize, identity: usize) -> Result<usize, Error> {
    match shape {
        0 => Ok(64),
        1 => Ok(65),
        2 => [0, 1, 63, 64, 65, 80, 129, 1024]
            .get(identity)
            .copied()
            .ok_or(Error::SecretMemory),
        3 => Ok(129),
        _ => Err(Error::SecretMemory),
    }
}

fn message_bits(shape: usize, identity: usize) -> Result<usize, Error> {
    match shape {
        0 => Ok(1024),
        1 => [0, 1, 55, 56, 63, 64, 65, 129]
            .get(identity)
            .and_then(|bytes: &usize| bytes.checked_mul(8))
            .ok_or(Error::SecretMemory),
        2 => [1, 7, 8, 9, 447, 448, 511, 513]
            .get(identity)
            .copied()
            .ok_or(Error::SecretMemory),
        _ => Err(Error::SecretMemory),
    }
}

pub(super) fn run(executor: &Md5Executor) -> Result<(), Error> {
    for key_shape in 0..4 {
        for message_shape in 0..3 {
            for rotation in 0..8 {
                case(executor, key_shape, message_shape, rotation)?;
            }
        }
    }
    println!(
        "LEGACY_MD5_BATCH_LANES: 96 batches, 768 distinct-lane records; 7 tag widths; public/secret/verify"
    );
    Ok(())
}

fn case(
    executor: &Md5Executor,
    key_shape: usize,
    message_shape: usize,
    rotation: usize,
) -> Result<(), Error> {
    let mut keys: [Vec<u8>; 8] = core::array::from_fn(|_| Vec::new());
    let mut messages: [Vec<u8>; 8] = core::array::from_fn(|_| Vec::new());
    let mut valid_bits = [0u8; 8];
    for (lane, ((key, message), valid)) in keys
        .iter_mut()
        .zip(&mut messages)
        .zip(&mut valid_bits)
        .enumerate()
    {
        let key_id = rotate(lane, rotation)?;
        let message_id = rotate(lane, rotation.checked_mul(2).ok_or(Error::SecretMemory)?)?;
        *key = pattern(key_size(key_shape, key_id)?, key_id, key_shape)?;
        let bits = message_bits(message_shape, message_id)?;
        *message = pattern(
            bits.div_ceil(8),
            message_id,
            message_shape.checked_add(4).ok_or(Error::SecretMemory)?,
        )?;
        *valid = match (bits, bits % 8) {
            (0, _) => 0,
            (_, 0) => 8,
            (_, tail) => u8::try_from(tail).map_err(|_| Error::SecretMemory)?,
        };
        if *valid != 0 && *valid != 8 {
            *message.last_mut().ok_or(Error::SecretMemory)? &=
                255 << 8u8.checked_sub(*valid).ok_or(Error::SecretMemory)?;
        }
    }
    let mut inputs = core::array::from_fn(|_| None);
    for (((key, bytes), valid), input) in
        keys.iter().zip(&messages).zip(valid_bits).zip(&mut inputs)
    {
        *input = Some(Input::new(
            key,
            BitString::new(bytes, valid).map_err(|_| Error::MessageTooLong)?,
        ));
    }
    let mut full = [[0xa5; 16]; 8];
    let (_, expected_report) =
        select(executor, 16)?.authenticate(&inputs, &mut full, &mut Md5BatchControl::new(10000))?;
    let width = executor
        .backend()
        .ok_or(Error::ExecutionUnavailable)?
        .lane_width();
    assert_eq!(expected_report.vector_width, width);
    assert_eq!(expected_report.inner.active_lanes, 8);
    assert_eq!(expected_report.outer.active_lanes, 8);
    assert!(expected_report.inner.vector_blocks >= width);
    assert!(expected_report.outer.vector_blocks >= width);
    let normalization_simd = keys
        .chunks(width)
        .any(|group| group.iter().all(|key| key.len() > 64));
    if normalization_simd {
        assert!(expected_report.normalization.vector_blocks >= width);
    } else {
        assert_eq!(expected_report.normalization.vector_blocks, 0);
        if keys.iter().any(|key| key.len() > 64) {
            assert!(expected_report.normalization.scalar_blocks > 0);
        } else {
            assert_eq!(expected_report.normalization.scalar_blocks, 0);
        }
    }
    for length in 10..=16 {
        let mut expected = full;
        for row in &mut expected {
            row.get_mut(length..).ok_or(Error::SecretMemory)?.fill(0);
        }
        let mut output = [[0xa5; 16]; 8];
        let (_, report) = select(executor, length)?.authenticate(
            &inputs,
            &mut output,
            &mut Md5BatchControl::new(10000),
        )?;
        assert_eq!(output, expected);
        assert_eq!(report, expected_report);
        let (secret, report) = select(executor, length)?.authenticate_secret(
            &inputs,
            &mut output,
            &mut Md5BatchControl::new(10000),
        )?;
        for (lane, row) in expected.iter().enumerate() {
            assert_eq!(secret.expose(lane), row.get(..length));
        }
        assert_eq!(report, expected_report);
        drop(secret);
        assert_eq!(output, [[0; 16]; 8]);
        let candidates = full.each_ref().map(|row| row.get(..length));
        let verified = select(executor, length)?.verify(
            &inputs,
            &candidates,
            &mut Md5BatchControl::new(10000),
        );
        assert_eq!(verified, Ok(expected_report));
        for lane in 0..8 {
            let mut wrong = candidates;
            let other = candidates
                .get(rotate(lane, 1)?)
                .copied()
                .ok_or(Error::SecretMemory)?;
            assert_ne!(candidates.get(lane), Some(&other));
            *wrong.get_mut(lane).ok_or(Error::SecretMemory)? = other;
            assert!(matches!(
                select(executor, length)?
                    .verify(&inputs, &wrong, &mut Md5BatchControl::new(10000),),
                Err(brynja_legacy_hmac::VerificationError::Mismatch(_))
            ));
        }
    }
    for (lane, tag) in full.iter().enumerate() {
        print!("LEGACY_MD5_BATCH_LANE:{key_shape}:{message_shape}:{rotation}:{lane}:");
        for byte in tag {
            print!("{byte:02x}");
        }
        println!();
    }
    Ok(())
}
