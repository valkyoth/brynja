//! Hosted final acceptance; the unchanged portable contract remains no_std.

use brynja_crypto_cpu::{
    ADMITTED_BACKEND_COUNT, IMPLEMENTED_KECCAK_BACKEND_COUNT, KeccakBackend, KeccakBackendSession,
};

mod parallel;

/// Closed downstream evidence failure; never carries secret data.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    /// The frozen portable contract failed.
    Portable,
    /// Backend disposition changed without new admission evidence.
    Backend,
    /// A parallel public operation differed or failed.
    Parallel,
    /// A failure released output or had the wrong classification.
    Failure,
}

/// Counts derived from executed acceptance cases, not performance claims.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Report {
    /// Named functions in the unchanged portable contract.
    pub identities: usize,
    /// Exact sequential/caller-scheduled/native output comparisons.
    pub parallel_cases: usize,
    /// Rejected operations with preserved public destinations.
    pub failure_cases: usize,
    /// Explicitly rejected accelerated candidates.
    pub unadmitted_candidates: usize,
}

/// Runs acceptance without evidence-only CPU cfgs or unsafe ISA attestations.
pub fn run() -> Result<Report, Error> {
    let portable = brynja_sp800185_public_api_fixture::run().map_err(|_| Error::Portable)?;
    if portable.identities != 14
        || portable.hardened_profiles != 14
        || portable.official_examples != 14
        || portable.public_layers != 3
    {
        return Err(Error::Portable);
    }
    let backends = [KeccakBackend::X86Avx2, KeccakBackend::Aarch64Sha3];
    if ADMITTED_BACKEND_COUNT != 0
        || IMPLEMENTED_KECCAK_BACKEND_COUNT != backends.len()
        || backends.iter().any(|backend| backend.is_admitted())
        || KeccakBackendSession::for_compiled_target().is_some()
    {
        return Err(Error::Backend);
    }
    Ok(Report {
        identities: portable.identities,
        parallel_cases: parallel::compare()?,
        failure_cases: parallel::failures()?,
        unadmitted_candidates: backends.len(),
    })
}

#[cfg(test)]
mod tests {
    #[test]
    fn frozen_contract_and_all_execution_modes_agree() {
        assert_eq!(
            super::run(),
            Ok(super::Report {
                identities: 14,
                parallel_cases: 540,
                failure_cases: 24,
                unadmitted_candidates: 2,
            })
        );
    }
}
