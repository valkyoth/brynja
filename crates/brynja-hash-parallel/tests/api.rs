//! Adversarial and lifecycle acceptance for the portable API.

use brynja_hash_parallel::{
    Fips202BitString, Fips202Output, HardenedParallelHash128, ParallelHash128,
    ParallelHash128Collector, ParallelHash128Plan, ParallelHashError, ParallelHashXof128,
    parallel_hash128,
};

#[test]
fn streamed_scheduled_and_one_shot_are_identical() -> Result<(), ParallelHashError> {
    let input = b"caller scheduled leaves may finish in any order";
    let mut expected = [0_u8; 32];
    let mut one_shot_workspace = [0_u8; 7];
    assert_eq!(
        parallel_hash128(input, &mut one_shot_workspace, b"scheduled", &mut expected),
        Ok(())
    );

    let mut streamed_workspace = [0_u8; 7];
    let mut streamed = ParallelHash128::new(&mut streamed_workspace, b"scheduled")?;
    for fragment in input.chunks(3) {
        assert_eq!(streamed.update(fragment), Ok(()));
    }
    let mut actual = [0_u8; 32];
    assert_eq!(streamed.finalize(&mut actual), Ok(()));
    assert_eq!(actual, expected);

    let plan = ParallelHash128Plan::new(input, 7)?;
    let mut collector = ParallelHash128Collector::new(&plan, b"scheduled")?;
    for index in 0..plan.leaf_count() {
        let mut storage = [0_u8; 32];
        let result = plan.job(index)?.execute(&mut storage)?;
        assert_eq!(collector.merge(&result), Ok(()));
        drop(result);
        assert!(storage.iter().all(|byte| *byte == 0));
    }
    let mut scheduled = [0_u8; 32];
    assert_eq!(collector.finalize(&mut scheduled), Ok(()));
    assert_eq!(scheduled, expected);
    Ok(())
}

#[test]
fn empty_input_has_zero_leaves_and_b_one_is_valid() -> Result<(), ParallelHashError> {
    let plan = ParallelHash128Plan::new(b"", 1)?;
    assert_eq!(plan.leaf_count(), 0);
    assert_eq!(plan.job(0).err(), Some(ParallelHashError::LeafOrder));

    let plan = ParallelHash128Plan::new(&[], 1)?;
    let mut collector = ParallelHash128Collector::new(&plan, b"")?;
    let mut scheduled = [0_u8; 32];
    assert_eq!(collector.finalize(&mut scheduled), Ok(()));
    let mut workspace = [0_u8; 1];
    let mut sequential = [0_u8; 32];
    assert_eq!(
        parallel_hash128(b"", &mut workspace, b"", &mut sequential),
        Ok(())
    );
    assert_eq!(scheduled, sequential);
    Ok(())
}

#[test]
fn reordered_leaf_permanently_fails_closed() -> Result<(), ParallelHashError> {
    let plan = ParallelHash128Plan::new(b"two leaves", 4)?;
    let mut collector = ParallelHash128Collector::new(&plan, b"")?;
    let mut storage = [0_u8; 32];
    let result = plan.job(1)?.execute(&mut storage)?;
    assert_eq!(collector.merge(&result), Err(ParallelHashError::LeafOrder));
    drop(result);
    assert_eq!(
        collector.finalize(&mut [0_u8; 32]),
        Err(ParallelHashError::StateConsumed)
    );
    Ok(())
}

#[test]
fn equal_shape_cross_plan_result_permanently_fails_closed() -> Result<(), ParallelHashError> {
    let first = ParallelHash128Plan::new(b"first plan!!", 4)?;
    let second = ParallelHash128Plan::new(b"other plan!!", 4)?;
    assert_eq!(first.leaf_count(), second.leaf_count());
    let mut collector = ParallelHash128Collector::new(&first, b"")?;
    let mut storage = [0_u8; 32];
    let result = second.job(0)?.execute(&mut storage)?;
    assert_eq!(
        collector.merge(&result),
        Err(ParallelHashError::LeafIdentity)
    );
    drop(result);
    assert!(storage.iter().all(|byte| *byte == 0));
    assert_eq!(
        collector.finalize(&mut [0_u8; 32]),
        Err(ParallelHashError::StateConsumed)
    );
    Ok(())
}

#[test]
fn arbitrary_bit_input_and_output_partition_are_stable() -> Result<(), ParallelHashError> {
    let mut workspace = [0_u8; 3];
    let mut state = ParallelHashXof128::new(&mut workspace, b"bits")?;
    assert_eq!(state.update(b"abc"), Ok(()));
    let tail =
        Fips202BitString::new(&[0x05], 3).map_err(|_| ParallelHashError::InvalidBitString)?;
    let mut reader = state.finalize_bits_xof(tail)?;
    let mut first = [0_u8; 7];
    let mut final_byte = [0_u8; 1];
    assert_eq!(reader.squeeze(&mut first), Ok(()));
    assert_eq!(
        reader.squeeze_final_bits(
            Fips202Output::new(&mut final_byte, 5)
                .map_err(|_| ParallelHashError::InvalidBitString)?,
        ),
        Ok(())
    );
    assert_eq!(final_byte[0] & 0xe0, 0);
    Ok(())
}

#[test]
fn hardened_output_and_workspace_clear_on_drop() -> Result<(), ParallelHashError> {
    let mut workspace = [0xa5_u8; 8];
    let mut output = [0_u8; 32];
    {
        let mut state = HardenedParallelHash128::new(&mut workspace, b"secret")?;
        assert_eq!(state.update(b"secret-derived material"), Ok(()));
        let owned = state.finalize_secret(&mut output)?;
        assert_ne!(owned.expose(), &[0_u8; 32]);
    }
    assert!(workspace.iter().all(|byte| *byte == 0));
    assert!(output.iter().all(|byte| *byte == 0));
    Ok(())
}

#[test]
fn zero_block_size_is_rejected_before_output() {
    let mut workspace = [];
    assert_eq!(
        ParallelHash128::new(&mut workspace, b"").err(),
        Some(ParallelHashError::InvalidBlockSize)
    );
}
