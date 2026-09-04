use brynja_hash_parallel_std::{CancellationToken, ParallelHashExecutor, ParallelHashExecutorError};

/// Executes ParallelHash through the opt-in native adapter.
pub fn execute(input: &[u8], output: &mut [u8; 32]) -> Result<(), ParallelHashExecutorError> {
    ParallelHashExecutor::new(2, 1_024)?.parallel_hash128(
        input,
        3,
        b"package-external",
        output,
        &CancellationToken::new(),
    )
}

#[cfg(test)]
mod tests {
    #[test]
    fn external_native_executor_is_operational() {
        let mut output = [0_u8; 32];
        assert_eq!(super::execute(b"parallel package closure", &mut output), Ok(()));
        assert!(output.iter().any(|byte| *byte != 0));
    }
}
