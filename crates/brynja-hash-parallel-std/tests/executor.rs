//! Bounded native executor acceptance.

use brynja_hash_parallel::{
    Fips202BitString, Fips202Output, ParallelHash128, ParallelHashXof128, parallel_hash_xof128,
    parallel_hash128,
};
use brynja_hash_parallel_std::{
    CancellationToken, ParallelHashExecutor, ParallelHashExecutorError,
};

#[test]
fn worker_counts_match_portable_fixed_and_xof() {
    let input = b"native workers finish independently but merge deterministically";
    let mut workspace = [0_u8; 5];
    let mut fixed = [0_u8; 32];
    let mut xof = [0_u8; 47];
    assert_eq!(
        parallel_hash128(input, &mut workspace, b"std", &mut fixed),
        Ok(())
    );
    assert_eq!(
        parallel_hash_xof128(input, &mut workspace, b"std", &mut xof),
        Ok(())
    );

    for workers in [1, 2, 4, 32] {
        let executor = ParallelHashExecutor::new(workers);
        assert!(executor.is_ok());
        let Ok(executor) = executor else {
            return;
        };
        let token = CancellationToken::new();
        let mut actual_fixed = [0_u8; 32];
        let mut actual_xof = [0_u8; 47];
        assert_eq!(
            executor.parallel_hash128(input, 5, b"std", &mut actual_fixed, &token),
            Ok(())
        );
        assert_eq!(
            executor.parallel_hash_xof128(input, 5, b"std", &mut actual_xof, &token),
            Ok(())
        );
        assert_eq!(actual_fixed, fixed);
        assert_eq!(actual_xof, xof);
    }
}

#[test]
fn cancellation_is_fail_closed_and_preserves_output() {
    let executor = ParallelHashExecutor::new(2);
    assert!(executor.is_ok());
    let Ok(executor) = executor else {
        return;
    };
    let token = CancellationToken::new();
    token.cancel();
    let mut output = [0xa5_u8; 32];
    assert_eq!(
        executor.parallel_hash128(b"input", 1, b"", &mut output, &token),
        Err(ParallelHashExecutorError::Cancelled)
    );
    assert_eq!(output, [0xa5; 32]);
}

#[test]
fn arbitrary_bit_executor_matches_portable_fixed_and_xof() {
    let input_bytes = [0x13, 0x05];
    let customization_bytes = [0x03];
    let input = Fips202BitString::new(&input_bytes, 3);
    let customization = Fips202BitString::new(&customization_bytes, 2);
    assert!(input.is_ok());
    assert!(customization.is_ok());
    let (Ok(input), Ok(customization)) = (input, customization) else {
        return;
    };

    let mut fixed_workspace = [0_u8; 1];
    let state = ParallelHash128::new_bits(&mut fixed_workspace, customization);
    assert!(state.is_ok());
    let Ok(mut state) = state else {
        return;
    };
    let mut expected_fixed = [0_u8; 18];
    let fixed_output = Fips202Output::new(&mut expected_fixed, 5);
    assert!(fixed_output.is_ok());
    let Ok(fixed_output) = fixed_output else {
        return;
    };
    assert_eq!(state.finalize_bits(input, fixed_output), Ok(()));

    let mut xof_workspace = [0_u8; 1];
    let xof = ParallelHashXof128::new_bits(&mut xof_workspace, customization);
    assert!(xof.is_ok());
    let Ok(mut xof) = xof else {
        return;
    };
    let reader = xof.finalize_bits_xof(input);
    assert!(reader.is_ok());
    let Ok(reader) = reader else {
        return;
    };
    let mut expected_xof = [0_u8; 19];
    let xof_output = Fips202Output::new(&mut expected_xof, 7);
    assert!(xof_output.is_ok());
    let Ok(xof_output) = xof_output else {
        return;
    };
    assert_eq!(reader.squeeze_final_bits(xof_output), Ok(()));

    let executor = ParallelHashExecutor::new(3);
    assert!(executor.is_ok());
    let Ok(executor) = executor else {
        return;
    };
    let token = CancellationToken::new();
    let mut actual_fixed = [0_u8; 18];
    let fixed_output = Fips202Output::new(&mut actual_fixed, 5);
    assert!(fixed_output.is_ok());
    let Ok(fixed_output) = fixed_output else {
        return;
    };
    assert_eq!(
        executor.parallel_hash128_bits(input, 1, customization, fixed_output, &token),
        Ok(())
    );
    let mut actual_xof = [0_u8; 19];
    let xof_output = Fips202Output::new(&mut actual_xof, 7);
    assert!(xof_output.is_ok());
    let Ok(xof_output) = xof_output else {
        return;
    };
    assert_eq!(
        executor.parallel_hash_xof128_bits(input, 1, customization, xof_output, &token),
        Ok(())
    );
    assert_eq!(actual_fixed, expected_fixed);
    assert_eq!(actual_xof, expected_xof);

    let mut output256 = [0_u8; 33];
    let output = Fips202Output::new(&mut output256, 4);
    assert!(output.is_ok());
    let Ok(output) = output else {
        return;
    };
    assert_eq!(
        executor.parallel_hash256_bits(input, 1, customization, output, &token),
        Ok(())
    );
    assert_eq!(output256[32] & 0xf0, 0);

    let mut xof256 = [0_u8; 35];
    let output = Fips202Output::new(&mut xof256, 6);
    assert!(output.is_ok());
    let Ok(output) = output else {
        return;
    };
    assert_eq!(
        executor.parallel_hash_xof256_bits(input, 1, customization, output, &token),
        Ok(())
    );
    assert_eq!(xof256[34] & 0xc0, 0);
}

#[test]
fn zero_workers_are_rejected() {
    assert_eq!(
        ParallelHashExecutor::new(0).err(),
        Some(ParallelHashExecutorError::InvalidWorkerCount)
    );
}
