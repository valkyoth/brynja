//! Downstream-style complete SHA-2 public API acceptance fixture.

#![no_std]

mod algorithms;
mod vectors;

use brynja::crypto as facade;
use brynja_hash_sha2 as leaf;

const REAL_TEXT: &[u8] = b"Brynja complete SHA-2 consumer acceptance\n";
const REPRESENTATIVE_FILE: &[u8] = include_bytes!("../fixtures/representative.txt");
const ZERO_BINARY: [u8; 256] = [0; 256];
const THOUSAND_A: [u8; 1_000] = [b'a'; 1_000];
pub(crate) const IRREGULAR_WIDTHS: [usize; 11] = [1, 7, 2, 31, 3, 64, 5, 127, 11, 4, 67];

/// Closed failure from the complete-family acceptance fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AcceptanceError {
    /// An independently generated expected digest did not match.
    DigestMismatch,
    /// The main facade and reusable family package disagreed.
    FacadeMismatch,
    /// Irregular streaming differed from one-shot behavior.
    StreamingMismatch,
    /// Public checked-length behavior was not exact and transactional.
    ExhaustionMismatch,
    /// Two distinct algorithm identities collapsed into truncation.
    IdentityMismatch,
    /// Backend availability or admission reporting was inaccurate.
    BackendReportMismatch,
    /// One or more public implementation claims were absent.
    ImplementationClaimMissing,
}

/// Successful complete-family acceptance counts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptanceReport {
    /// Number of distinct FIPS 180-4 identities checked.
    pub algorithms: usize,
    /// Number of independent one-shot results checked.
    pub one_shot_results: usize,
    /// Number of irregular or million-byte streaming results checked.
    pub streaming_results: usize,
    /// Number of admitted accelerated identities executed on this host.
    pub admitted_backends: usize,
    /// Number of implemented but unadmitted identities explicitly skipped.
    pub skipped_unadmitted_backends: usize,
}

/// Runs complete v0.23.4 SHA-2 downstream usability acceptance.
pub fn run() -> Result<AcceptanceReport, AcceptanceError> {
    check_claims()?;
    let cases = [
        (b"".as_slice(), &vectors::EMPTY),
        (b"abc".as_slice(), &vectors::ABC),
        (REAL_TEXT, &vectors::TEXT),
        (ZERO_BINARY.as_slice(), &vectors::ZERO_BINARY),
        (REPRESENTATIVE_FILE, &vectors::FILE),
    ];
    for (input, expected) in cases {
        algorithms::check_all(input, expected)?;
    }
    check_million_a()?;
    check_exhaustion()?;
    check_distinct_identities()?;
    let (admitted_backends, skipped_unadmitted_backends) = check_backends()?;
    Ok(AcceptanceReport {
        algorithms: 6,
        one_shot_results: 30,
        streaming_results: 36,
        admitted_backends,
        skipped_unadmitted_backends,
    })
}

fn check_claims() -> Result<(), AcceptanceError> {
    let leaf_claims = [
        leaf::SHA224_IMPLEMENTED,
        leaf::SHA256_IMPLEMENTED,
        leaf::SHA384_IMPLEMENTED,
        leaf::SHA512_IMPLEMENTED,
        leaf::SHA512_224_IMPLEMENTED,
        leaf::SHA512_256_IMPLEMENTED,
    ];
    let facade_claims = [
        facade::SHA224_IMPLEMENTED,
        facade::SHA256_IMPLEMENTED,
        facade::SHA384_IMPLEMENTED,
        facade::SHA512_IMPLEMENTED,
        facade::SHA512_224_IMPLEMENTED,
        facade::SHA512_256_IMPLEMENTED,
    ];
    if leaf_claims.iter().all(|claim| *claim) && facade_claims.iter().all(|claim| *claim) {
        Ok(())
    } else {
        Err(AcceptanceError::ImplementationClaimMissing)
    }
}

fn check_million_a() -> Result<(), AcceptanceError> {
    let mut sha224 = leaf::Sha224::new();
    let mut sha256 = leaf::Sha256::new();
    let mut sha384 = leaf::Sha384::new();
    let mut sha512 = leaf::Sha512::new();
    let mut sha512_224 = leaf::Sha512_224::new();
    let mut sha512_256 = leaf::Sha512_256::new();
    for _ in 0..1_000 {
        sha224.update(&THOUSAND_A).map_err(|_| AcceptanceError::StreamingMismatch)?;
        sha256.update(&THOUSAND_A).map_err(|_| AcceptanceError::StreamingMismatch)?;
        sha384.update(&THOUSAND_A).map_err(|_| AcceptanceError::StreamingMismatch)?;
        sha512.update(&THOUSAND_A).map_err(|_| AcceptanceError::StreamingMismatch)?;
        sha512_224.update(&THOUSAND_A).map_err(|_| AcceptanceError::StreamingMismatch)?;
        sha512_256.update(&THOUSAND_A).map_err(|_| AcceptanceError::StreamingMismatch)?;
    }
    let expected = &vectors::MILLION_A;
    if !algorithms::matches_hex(sha224.finalize().as_bytes(), expected.sha224)
        || !algorithms::matches_hex(sha256.finalize().as_bytes(), expected.sha256)
        || !algorithms::matches_hex(sha384.finalize().as_bytes(), expected.sha384)
        || !algorithms::matches_hex(sha512.finalize().as_bytes(), expected.sha512)
        || !algorithms::matches_hex(sha512_224.finalize().as_bytes(), expected.sha512_224)
        || !algorithms::matches_hex(sha512_256.finalize().as_bytes(), expected.sha512_256)
    {
        return Err(AcceptanceError::DigestMismatch);
    }
    Ok(())
}

fn check_exhaustion() -> Result<(), AcceptanceError> {
    check_sha224_exhaustion()?;
    check_sha256_exhaustion()?;
    check_sha384_exhaustion()?;
    check_sha512_exhaustion()?;
    check_sha512_224_exhaustion()?;
    check_sha512_256_exhaustion()
}

fn check_sha224_exhaustion() -> Result<(), AcceptanceError> {
    let mut state = leaf::Sha224::new();
    if state.check_additional_bytes(leaf::Sha224::MAX_MESSAGE_BYTES).is_err()
        || state.check_additional_bytes(leaf::Sha224::MAX_MESSAGE_BYTES + 1)
            != Err(leaf::Sha224Error::MessageTooLong)
    {
        return Err(AcceptanceError::ExhaustionMismatch);
    }
    state.update(b"abc").map_err(|_| AcceptanceError::ExhaustionMismatch)?;
    if state.check_additional_bytes(leaf::Sha224::MAX_MESSAGE_BYTES - 2)
        != Err(leaf::Sha224Error::MessageTooLong)
        || state.message_bytes() != 3
    {
        return Err(AcceptanceError::ExhaustionMismatch);
    }
    Ok(())
}

fn check_sha256_exhaustion() -> Result<(), AcceptanceError> {
    let mut state = leaf::Sha256::new();
    if state.check_additional_bytes(leaf::Sha256::MAX_MESSAGE_BYTES).is_err()
        || state.check_additional_bytes(leaf::Sha256::MAX_MESSAGE_BYTES + 1)
            != Err(leaf::Sha256Error::MessageTooLong)
    {
        return Err(AcceptanceError::ExhaustionMismatch);
    }
    state.update(b"abc").map_err(|_| AcceptanceError::ExhaustionMismatch)?;
    if state.check_additional_bytes(leaf::Sha256::MAX_MESSAGE_BYTES - 2)
        != Err(leaf::Sha256Error::MessageTooLong)
        || state.message_bytes() != 3
    {
        return Err(AcceptanceError::ExhaustionMismatch);
    }
    Ok(())
}

macro_rules! check_wide_exhaustion {
    ($function:ident, $state:ty, $error:path) => {
        fn $function() -> Result<(), AcceptanceError> {
            let mut state = <$state>::new();
            if state.check_additional_bytes(<$state>::MAX_MESSAGE_BYTES).is_err()
                || state.check_additional_bytes(<$state>::MAX_MESSAGE_BYTES + 1)
                    != Err($error)
            {
                return Err(AcceptanceError::ExhaustionMismatch);
            }
            state.update(b"abc").map_err(|_| AcceptanceError::ExhaustionMismatch)?;
            if state.check_additional_bytes(<$state>::MAX_MESSAGE_BYTES - 2)
                != Err($error)
                || state.message_bytes() != 3
            {
                return Err(AcceptanceError::ExhaustionMismatch);
            }
            Ok(())
        }
    };
}

check_wide_exhaustion!(check_sha384_exhaustion, leaf::Sha384, leaf::Sha384Error::MessageTooLong);
check_wide_exhaustion!(check_sha512_exhaustion, leaf::Sha512, leaf::Sha512Error::MessageTooLong);
check_wide_exhaustion!(
    check_sha512_224_exhaustion,
    leaf::Sha512_224,
    leaf::Sha512_224Error::MessageTooLong
);
check_wide_exhaustion!(
    check_sha512_256_exhaustion,
    leaf::Sha512_256,
    leaf::Sha512_256Error::MessageTooLong
);

fn check_distinct_identities() -> Result<(), AcceptanceError> {
    let sha224 = leaf::sha224(b"abc").map_err(|_| AcceptanceError::IdentityMismatch)?;
    let sha256 = leaf::sha256(b"abc").map_err(|_| AcceptanceError::IdentityMismatch)?;
    let sha384 = leaf::sha384(b"abc").map_err(|_| AcceptanceError::IdentityMismatch)?;
    let sha512 = leaf::sha512(b"abc").map_err(|_| AcceptanceError::IdentityMismatch)?;
    let sha512_224 = leaf::sha512_224(b"abc").map_err(|_| AcceptanceError::IdentityMismatch)?;
    let sha512_256 = leaf::sha512_256(b"abc").map_err(|_| AcceptanceError::IdentityMismatch)?;
    let (sha256_prefix, _) = sha256.as_bytes().split_at(leaf::Sha224Digest::LENGTH);
    let (sha512_384_prefix, _) = sha512.as_bytes().split_at(leaf::Sha384Digest::LENGTH);
    let (sha512_224_prefix, _) = sha512.as_bytes().split_at(leaf::Sha512_224Digest::LENGTH);
    let (sha512_256_prefix, _) = sha512.as_bytes().split_at(leaf::Sha512_256Digest::LENGTH);
    if sha224.as_ref() == sha256_prefix
        || sha384.as_ref() == sha512_384_prefix
        || sha512_224.as_ref() == sha512_224_prefix
        || sha512_256.as_ref() == sha512_256_prefix
    {
        return Err(AcceptanceError::IdentityMismatch);
    }
    Ok(())
}

fn check_backends() -> Result<(usize, usize), AcceptanceError> {
    let sha256_backends = [
        leaf::Sha256Backend::X86Sha,
        leaf::Sha256Backend::Aarch64Sha2,
        leaf::Sha256Backend::RiscVScalarCrypto,
    ];
    let sha512_backends = [
        leaf::Sha512Backend::Aarch64Sha512,
        leaf::Sha512Backend::RiscVScalarCrypto,
    ];
    let admitted = sha256_backends.iter().filter(|backend| backend.is_admitted()).count()
        + sha512_backends.iter().filter(|backend| backend.is_admitted()).count();
    let skipped = 5_usize.saturating_sub(admitted);
    if admitted != 0
        || skipped != 5
        || leaf::Sha256BackendSession::for_compiled_target().is_some()
        || leaf::Sha512BackendSession::for_compiled_target().is_some()
    {
        return Err(AcceptanceError::BackendReportMismatch);
    }
    let _sha224_backend_entry = leaf::sha224_with_backend;
    let _sha256_backend_entry = leaf::sha256_with_backend;
    let _sha384_backend_entry = leaf::sha384_with_backend;
    let _sha512_backend_entry = leaf::sha512_with_backend;
    let _sha512_224_backend_entry = leaf::sha512_224_with_backend;
    let _sha512_256_backend_entry = leaf::sha512_256_with_backend;
    Ok((admitted, skipped))
}

#[cfg(test)]
mod tests {
    use super::{AcceptanceReport, run};

    #[test]
    fn complete_sha2_public_acceptance_passes() {
        assert_eq!(
            run(),
            Ok(AcceptanceReport {
                algorithms: 6,
                one_shot_results: 30,
                streaming_results: 36,
                admitted_backends: 0,
                skipped_unadmitted_backends: 5,
            })
        );
    }
}
