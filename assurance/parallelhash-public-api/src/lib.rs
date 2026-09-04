#![no_std]

use brynja_hash_parallel::{
    HardenedParallelHash128, ParallelHash128Collector, ParallelHash128Plan, ParallelHashError,
};

/// Exercises the portable leaf package.
pub fn leaf(input: &[u8], workspace: &mut [u8], output: &mut [u8; 32]) -> Result<(), ParallelHashError> {
    brynja_hash_parallel::parallel_hash128(input, workspace, b"package-external", output)
}

/// Exercises the cryptographic facade.
pub fn crypto(input: &[u8], workspace: &mut [u8], output: &mut [u8; 32]) -> Result<(), ParallelHashError> {
    brynja_crypto::parallel_hash128(input, workspace, b"package-external", output)
}

/// Exercises the main facade.
pub fn facade(input: &[u8], workspace: &mut [u8], output: &mut [u8; 32]) -> Result<(), ParallelHashError> {
    brynja::crypto::parallel_hash128(input, workspace, b"package-external", output)
}

/// Exercises caller-scheduled leaf ownership and deterministic collection.
pub fn scheduled(input: &[u8], output: &mut [u8; 32]) -> Result<(), ParallelHashError> {
    let plan = ParallelHash128Plan::new(input, 3)?;
    let mut collector = ParallelHash128Collector::new(&plan, b"package-external")?;
    for index in 0..plan.leaf_count() {
        let mut storage = [0_u8; 32];
        let result = plan.job(index)?.execute(&mut storage)?;
        collector.merge(&result)?;
    }
    collector.finalize(output)
}

/// Exercises secret output ownership and cleanup.
pub fn hardened(output: &mut [u8; 32]) -> Result<(), ParallelHashError> {
    let mut workspace = [0_u8; 3];
    let mut state = HardenedParallelHash128::new(&mut workspace, b"package-external")?;
    state.update(b"secret-derived input")?;
    let secret = state.finalize_secret(output)?;
    if secret.expose().len() != 32 {
        return Err(ParallelHashError::SecretMemory);
    }
    drop(secret);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn leaf_crypto_main_scheduled_and_hardened_apis_are_operational() {
        let input = b"parallel package closure";
        let mut leaf = [0_u8; 32];
        let mut crypto = [0_u8; 32];
        let mut facade = [0_u8; 32];
        let mut scheduled = [0_u8; 32];
        let mut secret = [0xa5_u8; 32];
        assert_eq!(super::leaf(input, &mut [0; 3], &mut leaf), Ok(()));
        assert_eq!(super::crypto(input, &mut [0; 3], &mut crypto), Ok(()));
        assert_eq!(super::facade(input, &mut [0; 3], &mut facade), Ok(()));
        assert_eq!(super::scheduled(input, &mut scheduled), Ok(()));
        assert_eq!(leaf, crypto);
        assert_eq!(leaf, facade);
        assert_eq!(leaf, scheduled);
        assert_eq!(super::hardened(&mut secret), Ok(()));
        assert!(secret.iter().all(|byte| *byte == 0));
    }
}
