//! Direct SHA-3/SHAKE candidate evidence over the frozen portable semantics.

use brynja_crypto_cpu::{KeccakBackend, KeccakBackendHealth, KeccakBackendSession};
use brynja_hash_sha3 as portable;

const SHA3_SUFFIX: u8 = 0x06;
const SHAKE_SUFFIX: u8 = 0x1f;

/// Closed candidate-fixture failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CandidateError {
    /// No compile-time-proven backend was available.
    BackendUnavailable,
    /// The selected backend did not match the requested architecture.
    BackendMismatch,
    /// The startup KAT did not leave the session healthy.
    BackendUnhealthy,
    /// One candidate permutation failed.
    PermutationFailure,
    /// Candidate output differed from portable output.
    DifferentialMismatch,
    /// The bounded evidence fixture requested an invalid slice.
    FixtureBounds,
}

/// Successful candidate differential counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CandidateReport {
    /// Exact backend exercised.
    pub backend: KeccakBackend,
    /// Fixed-output comparisons completed.
    pub fixed_output_results: usize,
    /// XOF comparisons completed.
    pub xof_results: usize,
}

/// Runs all six frozen byte-oriented identities through one forced candidate.
pub fn run() -> Result<CandidateReport, CandidateError> {
    let backend = expected_backend().ok_or(CandidateError::BackendUnavailable)?;
    let session = KeccakBackendSession::for_compiled_target()
        .ok_or(CandidateError::BackendUnavailable)?;
    if session.backend() != backend {
        return Err(CandidateError::BackendMismatch);
    }
    if session.health() != KeccakBackendHealth::Healthy {
        return Err(CandidateError::BackendUnhealthy);
    }

    let mut corpus = [0_u8; 385];
    for (index, byte) in corpus.iter_mut().enumerate() {
        *byte = u8::try_from((index.saturating_mul(197).saturating_add(29)) % 251).unwrap_or(0);
    }
    let mut fixed = 0_usize;
    let mut xof = 0_usize;
    for length in [
        0_usize, 1, 71, 72, 73, 103, 104, 105, 135, 136, 137, 143, 144, 145, 167, 168, 169,
        255, 343, 385,
    ] {
        let input = corpus.get(..length).ok_or(CandidateError::FixtureBounds)?;
        check_fixed(input, 144, 28, portable::sha3_224(input)?.as_bytes(), &session)?;
        check_fixed(input, 136, 32, portable::sha3_256(input)?.as_bytes(), &session)?;
        check_fixed(input, 104, 48, portable::sha3_384(input)?.as_bytes(), &session)?;
        check_fixed(input, 72, 64, portable::sha3_512(input)?.as_bytes(), &session)?;
        fixed = fixed.saturating_add(4);
    }
    for length in [0_usize, 1, 31, 32, 71, 72, 73, 135, 136, 137, 167, 168, 169, 343] {
        let mut expected = [0_u8; 343];
        let expected_slice = expected
            .get_mut(..length)
            .ok_or(CandidateError::FixtureBounds)?;
        portable::shake128(&corpus, expected_slice)?;
        check_xof(&corpus, 168, expected_slice, &session)?;
        portable::shake256(&corpus, expected_slice)?;
        check_xof(&corpus, 136, expected_slice, &session)?;
        xof = xof.saturating_add(2);
    }
    Ok(CandidateReport {
        backend,
        fixed_output_results: fixed,
        xof_results: xof,
    })
}

fn check_fixed(
    input: &[u8],
    rate: usize,
    output_length: usize,
    expected: &[u8],
    session: &KeccakBackendSession,
) -> Result<(), CandidateError> {
    let mut actual = [0_u8; 64];
    let output = actual
        .get_mut(..output_length)
        .ok_or(CandidateError::FixtureBounds)?;
    sponge(input, rate, SHA3_SUFFIX, output, session)?;
    if output == expected {
        Ok(())
    } else {
        Err(CandidateError::DifferentialMismatch)
    }
}

fn check_xof(
    input: &[u8],
    rate: usize,
    expected: &[u8],
    session: &KeccakBackendSession,
) -> Result<(), CandidateError> {
    let mut actual = [0_u8; 343];
    let output = actual
        .get_mut(..expected.len())
        .ok_or(CandidateError::FixtureBounds)?;
    sponge(input, rate, SHAKE_SUFFIX, output, session)?;
    if output == expected {
        Ok(())
    } else {
        Err(CandidateError::DifferentialMismatch)
    }
}

fn sponge(
    input: &[u8],
    rate: usize,
    suffix: u8,
    output: &mut [u8],
    session: &KeccakBackendSession,
) -> Result<(), CandidateError> {
    let mut state = [0_u64; 25];
    let mut blocks = input.chunks_exact(rate);
    for block in blocks.by_ref() {
        xor_bytes(&mut state, block);
        session
            .permute_for_evidence(&mut state)
            .map_err(|_| CandidateError::PermutationFailure)?;
    }
    let remainder = blocks.remainder();
    xor_bytes(&mut state, remainder);
    xor_byte(&mut state, remainder.len(), suffix)?;
    xor_byte(&mut state, rate.saturating_sub(1), 0x80)?;
    session
        .permute_for_evidence(&mut state)
        .map_err(|_| CandidateError::PermutationFailure)?;

    let mut position = 0_usize;
    for byte in output {
        if position == rate {
            session
                .permute_for_evidence(&mut state)
                .map_err(|_| CandidateError::PermutationFailure)?;
            position = 0;
        }
        *byte = state_byte(&state, position)?;
        position = position.saturating_add(1);
    }
    Ok(())
}

fn xor_bytes(state: &mut [u64; 25], input: &[u8]) {
    for (position, byte) in input.iter().enumerate() {
        let _ = xor_byte(state, position, *byte);
    }
}

fn xor_byte(state: &mut [u64; 25], position: usize, byte: u8) -> Result<(), CandidateError> {
    let lane = position / 8;
    let shift = u32::try_from((position % 8).saturating_mul(8))
        .map_err(|_| CandidateError::FixtureBounds)?;
    let target = state.get_mut(lane).ok_or(CandidateError::FixtureBounds)?;
    *target ^= u64::from(byte) << shift;
    Ok(())
}

fn state_byte(state: &[u64; 25], position: usize) -> Result<u8, CandidateError> {
    let lane = state
        .get(position / 8)
        .ok_or(CandidateError::FixtureBounds)?;
    lane.to_le_bytes()
        .get(position % 8)
        .copied()
        .ok_or(CandidateError::FixtureBounds)
}

fn expected_backend() -> Option<KeccakBackend> {
    #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))]
    return Some(KeccakBackend::X86Avx2);
    #[cfg(all(target_arch = "aarch64", target_feature = "neon", target_feature = "sha3"))]
    return Some(KeccakBackend::Aarch64Sha3);
    #[allow(unreachable_code)]
    None
}

impl From<portable::Sha3_224Error> for CandidateError {
    fn from(_: portable::Sha3_224Error) -> Self { Self::DifferentialMismatch }
}
impl From<portable::Sha3_256Error> for CandidateError {
    fn from(_: portable::Sha3_256Error) -> Self { Self::DifferentialMismatch }
}
impl From<portable::Sha3_384Error> for CandidateError {
    fn from(_: portable::Sha3_384Error) -> Self { Self::DifferentialMismatch }
}
impl From<portable::Sha3_512Error> for CandidateError {
    fn from(_: portable::Sha3_512Error) -> Self { Self::DifferentialMismatch }
}
impl From<portable::Shake128Error> for CandidateError {
    fn from(_: portable::Shake128Error) -> Self { Self::DifferentialMismatch }
}
impl From<portable::Shake256Error> for CandidateError {
    fn from(_: portable::Shake256Error) -> Self { Self::DifferentialMismatch }
}
