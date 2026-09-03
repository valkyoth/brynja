//! Combined downstream acceptance for the complete SHA-2 and FIPS 202 APIs.

#![no_std]

use brynja_crypto_cpu::{
    ADMITTED_BACKEND_COUNT, IMPLEMENTED_BACKEND_COUNT, IMPLEMENTED_KECCAK_BACKEND_COUNT,
    IMPLEMENTED_SHA256_BACKEND_COUNT, IMPLEMENTED_SHA512_BACKEND_COUNT, KeccakBackend,
    Sha256Backend, Sha512Backend,
};

/// A closed combined-acceptance failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AcceptanceError {
    /// Complete SHA-2 package-external behavior changed.
    Sha2,
    /// Complete ordinary SHA-3/SHAKE package-external behavior changed.
    Fips202,
    /// Complete hardened SHA-3/SHAKE behavior changed.
    HardenedFips202,
    /// An implementation or hardened-ownership claim disappeared.
    Claim,
    /// CPU backend inventory or admission changed without review.
    BackendDisposition,
}

/// Counts bound by the final family acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptanceReport {
    /// SHA-2 standardized identities exercised.
    pub sha2_identities: usize,
    /// SHA-3 and SHAKE standardized identities exercised.
    pub fips202_identities: usize,
    /// Implemented accelerated backend candidates explicitly inventoried.
    pub backend_candidates: usize,
    /// Candidates admitted for ordinary dispatch.
    pub admitted_backends: usize,
}

/// Runs the combined v0.24.11 family acceptance over final public packages.
pub fn run() -> Result<AcceptanceReport, AcceptanceError> {
    let sha2 = brynja_sha2_public_api_fixture::run().map_err(|_| AcceptanceError::Sha2)?;
    let fips202 = brynja_sha3_public_api_fixture::run().map_err(|_| AcceptanceError::Fips202)?;
    brynja_sha3_hardened_api_fixture::exercise_all(b"combined secret-bearing acceptance")
        .map_err(|_| AcceptanceError::HardenedFips202)?;
    check_claims()?;
    check_backend_dispositions()?;
    if sha2.algorithms != 6 || fips202.algorithms != 6 {
        return Err(AcceptanceError::Claim);
    }
    Ok(AcceptanceReport {
        sha2_identities: sha2.algorithms,
        fips202_identities: fips202.algorithms,
        backend_candidates: IMPLEMENTED_BACKEND_COUNT,
        admitted_backends: ADMITTED_BACKEND_COUNT,
    })
}

fn check_claims() -> Result<(), AcceptanceError> {
    let sha2 = [
        brynja_hash_sha2::SHA224_IMPLEMENTED,
        brynja_hash_sha2::SHA256_IMPLEMENTED,
        brynja_hash_sha2::SHA384_IMPLEMENTED,
        brynja_hash_sha2::SHA512_IMPLEMENTED,
        brynja_hash_sha2::SHA512_224_IMPLEMENTED,
        brynja_hash_sha2::SHA512_256_IMPLEMENTED,
        brynja_hash_sha2::SHA2_BIT_INPUT_IMPLEMENTED,
        brynja_hash_sha2::SHA2_HARDENED_STATE_IMPLEMENTED,
    ];
    let fips202 = [
        brynja_hash_sha3::SHA3_224_IMPLEMENTED,
        brynja_hash_sha3::SHA3_256_IMPLEMENTED,
        brynja_hash_sha3::SHA3_384_IMPLEMENTED,
        brynja_hash_sha3::SHA3_512_IMPLEMENTED,
        brynja_hash_sha3::SHAKE128_IMPLEMENTED,
        brynja_hash_sha3::SHAKE256_IMPLEMENTED,
        brynja_hash_sha3::FIPS202_BIT_INPUT_IMPLEMENTED,
        brynja_hash_sha3::FIPS202_BIT_OUTPUT_IMPLEMENTED,
        brynja_hash_sha3::FIPS202_HARDENED_STATE_IMPLEMENTED,
    ];
    if sha2.into_iter().all(core::convert::identity)
        && fips202.into_iter().all(core::convert::identity)
    {
        Ok(())
    } else {
        Err(AcceptanceError::Claim)
    }
}

fn check_backend_dispositions() -> Result<(), AcceptanceError> {
    let sha256 = [
        Sha256Backend::X86Sha,
        Sha256Backend::Aarch64Sha2,
        Sha256Backend::RiscVScalarCrypto,
    ];
    let sha512 = [
        Sha512Backend::Aarch64Sha512,
        Sha512Backend::RiscVScalarCrypto,
    ];
    let keccak = [KeccakBackend::X86Avx2, KeccakBackend::Aarch64Sha3];
    let exact_inventory = IMPLEMENTED_BACKEND_COUNT == 7
        && IMPLEMENTED_SHA256_BACKEND_COUNT == sha256.len()
        && IMPLEMENTED_SHA512_BACKEND_COUNT == sha512.len()
        && IMPLEMENTED_KECCAK_BACKEND_COUNT == keccak.len();
    let none_admitted = ADMITTED_BACKEND_COUNT == 0
        && sha256.into_iter().all(|backend| !backend.is_admitted())
        && sha512.into_iter().all(|backend| !backend.is_admitted())
        && keccak.into_iter().all(|backend| !backend.is_admitted());
    if exact_inventory && none_admitted {
        Ok(())
    } else {
        Err(AcceptanceError::BackendDisposition)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_final_family_profile_passes_together() {
        assert_eq!(
            super::run(),
            Ok(super::AcceptanceReport {
                sha2_identities: 6,
                fips202_identities: 6,
                backend_candidates: 7,
                admitted_backends: 0,
            })
        );
    }
}
