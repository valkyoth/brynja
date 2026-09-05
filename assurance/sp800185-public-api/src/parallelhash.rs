use brynja_hash_parallel::{
    HardenedParallelHash128, HardenedParallelHash256, HardenedParallelHashXof128,
    HardenedParallelHashXof256, ParallelHash128, ParallelHash128Collector, ParallelHash128Plan,
    ParallelHash256, ParallelHash256Collector, ParallelHash256Plan,
    ParallelHashPublicDeclassification, ParallelHashXof128, parallel_hash_xof128, parallel_hash_xof256,
    parallel_hash128, parallel_hash256,
};
use brynja_hash_sha3::{Fips202BitString, Fips202Output};

use crate::{AcceptanceError, hex_eq, vectors};

const SHORT: [u8; 24] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
    0x17, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
];

pub(crate) fn run() -> Result<(), AcceptanceError> {
    official_examples()?;
    streaming_scheduled_and_bits()?;
    hardened_profiles()?;
    Ok(())
}

fn official_examples() -> Result<(), AcceptanceError> {
    let mut fixed128 = [0_u8; 32];
    let mut fixed256 = [0_u8; 64];
    let mut xof128 = [0_u8; 32];
    let mut xof256 = [0_u8; 64];
    parallel_hash128(&SHORT, &mut [0; 8], b"", &mut fixed128)
        .map_err(|_| AcceptanceError::ParallelHash)?;
    parallel_hash256(&SHORT, &mut [0; 8], b"", &mut fixed256)
        .map_err(|_| AcceptanceError::ParallelHash)?;
    parallel_hash_xof128(&SHORT, &mut [0; 8], b"", &mut xof128)
        .map_err(|_| AcceptanceError::ParallelHash)?;
    parallel_hash_xof256(&SHORT, &mut [0; 8], b"", &mut xof256)
        .map_err(|_| AcceptanceError::ParallelHash)?;
    if !hex_eq(&fixed128, vectors::PARALLEL128)
        || !hex_eq(&fixed256, vectors::PARALLEL256)
        || !hex_eq(&xof128, vectors::PARALLELXOF128)
        || !hex_eq(&xof256, vectors::PARALLELXOF256)
    {
        return Err(AcceptanceError::ParallelHash);
    }
    Ok(())
}

fn streaming_scheduled_and_bits() -> Result<(), AcceptanceError> {
    let real_data = vectors::REAL_DATA;
    let mut expected128 = [0_u8; 47];
    parallel_hash_xof128(real_data, &mut [0; 7], b"acceptance", &mut expected128)
        .map_err(|_| AcceptanceError::ParallelHash)?;
    let mut workspace128 = [0_u8; 7];
    let mut state128 = ParallelHashXof128::new(&mut workspace128, b"acceptance")
        .map_err(|_| AcceptanceError::ParallelHash)?;
    state128.update(&real_data[..13]).map_err(|_| AcceptanceError::ParallelHash)?;
    state128.update(&real_data[13..]).map_err(|_| AcceptanceError::ParallelHash)?;
    let mut reader128 = state128.finalize_xof().map_err(|_| AcceptanceError::ParallelHash)?;
    let mut actual128 = [0_u8; 47];
    let (first, second) = actual128.split_at_mut(11);
    reader128.squeeze(first).map_err(|_| AcceptanceError::ParallelHash)?;
    reader128.squeeze(second).map_err(|_| AcceptanceError::ParallelHash)?;
    if actual128 != expected128 || scheduled128(real_data)? != expected128 {
        return Err(AcceptanceError::ParallelHash);
    }

    let mut expected256 = [0_u8; 79];
    parallel_hash_xof256(real_data, &mut [0; 7], b"acceptance", &mut expected256)
        .map_err(|_| AcceptanceError::ParallelHash)?;
    if scheduled256(real_data)? != expected256 {
        return Err(AcceptanceError::ParallelHash);
    }

    let custom = Fips202BitString::new(&[], 0).map_err(|_| AcceptanceError::ParallelHash)?;
    let tail = Fips202BitString::new(&[0x15], 5).map_err(|_| AcceptanceError::ParallelHash)?;
    let mut workspace = [0_u8; 1];
    let mut state = ParallelHash128::new_bits(&mut workspace, custom)
        .map_err(|_| AcceptanceError::ParallelHash)?;
    state.update(b"bit input").map_err(|_| AcceptanceError::ParallelHash)?;
    let mut bits = [0_u8; 19];
    let output = Fips202Output::new(&mut bits, 3).map_err(|_| AcceptanceError::ParallelHash)?;
    state.finalize_bits(tail, output).map_err(|_| AcceptanceError::ParallelHash)?;
    if bits[18] & 0xf8 != 0 {
        return Err(AcceptanceError::ParallelHash);
    }

    let mut empty = [0_u8; 1];
    parallel_hash128(b"", &mut [0; 1], b"", &mut empty)
        .map_err(|_| AcceptanceError::ParallelHash)?;
    if ParallelHash256::new(&mut [], b"").is_ok() {
        return Err(AcceptanceError::ParallelHash);
    }
    Ok(())
}

fn scheduled128(input: &[u8]) -> Result<[u8; 47], AcceptanceError> {
    let plan = ParallelHash128Plan::new(input, 7).map_err(|_| AcceptanceError::ParallelHash)?;
    let mut collector = ParallelHash128Collector::new(&plan, b"acceptance")
        .map_err(|_| AcceptanceError::ParallelHash)?;
    for index in 0..plan.leaf_count() {
        let mut storage = [0_u8; 32];
        let result = plan
            .job(index)
            .and_then(|job| job.execute(&mut storage))
            .map_err(|_| AcceptanceError::ParallelHash)?;
        collector.merge(&result).map_err(|_| AcceptanceError::ParallelHash)?;
    }
    let mut output = [0_u8; 47];
    let mut reader = collector.finalize_xof().map_err(|_| AcceptanceError::ParallelHash)?;
    reader
        .squeeze_public(&mut output, ParallelHashPublicDeclassification::acknowledge())
        .map_err(|_| AcceptanceError::ParallelHash)?;
    Ok(output)
}

fn scheduled256(input: &[u8]) -> Result<[u8; 79], AcceptanceError> {
    let plan = ParallelHash256Plan::new(input, 7).map_err(|_| AcceptanceError::ParallelHash)?;
    let mut collector = ParallelHash256Collector::new(&plan, b"acceptance")
        .map_err(|_| AcceptanceError::ParallelHash)?;
    for index in 0..plan.leaf_count() {
        let mut storage = [0_u8; 64];
        let result = plan
            .job(index)
            .and_then(|job| job.execute(&mut storage))
            .map_err(|_| AcceptanceError::ParallelHash)?;
        collector.merge(&result).map_err(|_| AcceptanceError::ParallelHash)?;
    }
    let mut output = [0_u8; 79];
    let mut reader = collector.finalize_xof().map_err(|_| AcceptanceError::ParallelHash)?;
    let (first, second) = output.split_at_mut(29);
    reader
        .squeeze_public(first, ParallelHashPublicDeclassification::acknowledge())
        .and_then(|()| {
            reader.squeeze_public(second, ParallelHashPublicDeclassification::acknowledge())
        })
        .map_err(|_| AcceptanceError::ParallelHash)?;
    Ok(output)
}

fn hardened_profiles() -> Result<(), AcceptanceError> {
    let mut expected_fixed128 = [0_u8; 32];
    let mut expected_fixed256 = [0_u8; 64];
    let mut expected_xof128 = [0_u8; 37];
    let mut expected_xof256 = [0_u8; 73];
    parallel_hash128(b"secret input", &mut [0; 7], b"secret", &mut expected_fixed128)
        .map_err(|_| AcceptanceError::ParallelHash)?;
    parallel_hash256(b"secret input", &mut [0; 7], b"secret", &mut expected_fixed256)
        .map_err(|_| AcceptanceError::ParallelHash)?;
    parallel_hash_xof128(b"secret input", &mut [0; 7], b"secret", &mut expected_xof128)
        .map_err(|_| AcceptanceError::ParallelHash)?;
    parallel_hash_xof256(b"secret input", &mut [0; 7], b"secret", &mut expected_xof256)
        .map_err(|_| AcceptanceError::ParallelHash)?;
    let mut fixed128 = [0xa5_u8; 32];
    let mut fixed256 = [0xa5_u8; 64];
    let mut xof128 = [0xa5_u8; 37];
    let mut xof256 = [0xa5_u8; 73];
    let mut workspace128 = [0xa5_u8; 7];
    {
        let mut state = HardenedParallelHash128::new(&mut workspace128, b"secret")
            .map_err(|_| AcceptanceError::ParallelHash)?;
        state.update(b"secret input").map_err(|_| AcceptanceError::ParallelHash)?;
        let secret = state
            .finalize_secret(&mut fixed128)
            .map_err(|_| AcceptanceError::ParallelHash)?;
        if secret.expose() != expected_fixed128 {
            return Err(AcceptanceError::ParallelHash);
        }
    }
    let mut workspace256 = [0xa5_u8; 7];
    {
        let mut state = HardenedParallelHash256::new(&mut workspace256, b"secret")
            .map_err(|_| AcceptanceError::ParallelHash)?;
        state.update(b"secret input").map_err(|_| AcceptanceError::ParallelHash)?;
        let secret = state
            .finalize_secret(&mut fixed256)
            .map_err(|_| AcceptanceError::ParallelHash)?;
        if secret.expose() != expected_fixed256 {
            return Err(AcceptanceError::ParallelHash);
        }
    }
    let mut xof_workspace128 = [0xa5_u8; 7];
    {
        let mut state = HardenedParallelHashXof128::new(&mut xof_workspace128, b"secret")
            .map_err(|_| AcceptanceError::ParallelHash)?;
        state.update(b"secret input").map_err(|_| AcceptanceError::ParallelHash)?;
        let mut reader = state.finalize_xof().map_err(|_| AcceptanceError::ParallelHash)?;
        let secret = reader
            .squeeze_secret(&mut xof128)
            .map_err(|_| AcceptanceError::ParallelHash)?;
        if secret.expose() != expected_xof128 {
            return Err(AcceptanceError::ParallelHash);
        }
    }
    let mut xof_workspace256 = [0xa5_u8; 7];
    {
        let mut state = HardenedParallelHashXof256::new(&mut xof_workspace256, b"secret")
            .map_err(|_| AcceptanceError::ParallelHash)?;
        state.update(b"secret input").map_err(|_| AcceptanceError::ParallelHash)?;
        let mut reader = state.finalize_xof().map_err(|_| AcceptanceError::ParallelHash)?;
        let secret = reader
            .squeeze_secret(&mut xof256)
            .map_err(|_| AcceptanceError::ParallelHash)?;
        if secret.expose() != expected_xof256 {
            return Err(AcceptanceError::ParallelHash);
        }
    }
    if fixed128 != [0; 32]
        || fixed256 != [0; 64]
        || xof128 != [0; 37]
        || xof256 != [0; 73]
        || workspace128 != [0; 7]
        || workspace256 != [0; 7]
        || xof_workspace128 != [0; 7]
        || xof_workspace256 != [0; 7]
    {
        return Err(AcceptanceError::ParallelHash);
    }
    Ok(())
}
