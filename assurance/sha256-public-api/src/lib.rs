//! Downstream-style SHA-256 public API acceptance fixture.

#![no_std]

use brynja_crypto::{Sha256 as CryptoSha256, sha256 as crypto_sha256};
use brynja_hash_sha2::{
    SHA256_IMPLEMENTED, Sha256, Sha256Backend, Sha256BackendSession, Sha256Digest, Sha256Error,
    sha256, sha256_with_backend,
};

const EMPTY_SHA256: &[u8; 64] = b"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
const ABC_SHA256: &[u8; 64] = b"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
const TEXT_SHA256: &[u8; 64] = b"c9be0da9b7d6b7de699ef2e31e5c656b738b0aa7c15e280655a1ad704ed8f045";
const ZERO_SHA256: &[u8; 64] = b"5341e6b2646979a70e57653007a1f310169421ec9bdd9f1a5648f75ade005af1";
const FILE_SHA256: &[u8; 64] = b"a8f34a54459e9655229bb554c15ebb87f89a0bfbc600da8eb56999422fc0487f";
const MILLION_A_SHA256: &[u8; 64] =
    b"cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0";

const REAL_TEXT: &[u8] = b"Brynja public SHA-256 consumer acceptance\n";
const REPRESENTATIVE_FILE: &[u8] = include_bytes!("../fixtures/representative.txt");
const ZERO_BINARY: [u8; 256] = [0; 256];
const THOUSAND_A: [u8; 1_000] = [b'a'; 1_000];
const IRREGULAR_WIDTHS: [usize; 11] = [1, 7, 2, 31, 3, 64, 5, 127, 11, 4, 67];

/// Closed failure from the public acceptance fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AcceptanceError {
    /// A published expected digest did not match.
    DigestMismatch,
    /// The reusable and composition APIs disagreed.
    FacadeMismatch,
    /// Streaming behavior differed from one-shot behavior.
    StreamingMismatch,
    /// Public checked-length behavior was not exact or transactional.
    ExhaustionMismatch,
    /// Backend availability or reporting overstated admission.
    BackendReportMismatch,
    /// A public implementation claim was absent.
    ImplementationClaimMissing,
}

/// Successful acceptance counts suitable for human-readable reporting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptanceReport {
    /// Number of representative fixed messages checked through both APIs.
    pub fixed_messages: usize,
    /// Number of irregular streaming comparisons.
    pub streaming_messages: usize,
    /// Number of admitted accelerated routes executed on this host.
    pub admitted_backends: usize,
    /// Number of implemented but unadmitted routes explicitly skipped.
    pub skipped_unadmitted_backends: usize,
}

/// Runs complete v0.22.3 SHA-256 downstream acceptance.
pub fn run() -> Result<AcceptanceReport, AcceptanceError> {
    if !SHA256_IMPLEMENTED || !brynja_crypto::SHA256_IMPLEMENTED {
        return Err(AcceptanceError::ImplementationClaimMissing);
    }

    let cases = [
        (b"".as_slice(), EMPTY_SHA256),
        (b"abc".as_slice(), ABC_SHA256),
        (REAL_TEXT, TEXT_SHA256),
        (ZERO_BINARY.as_slice(), ZERO_SHA256),
        (REPRESENTATIVE_FILE, FILE_SHA256),
    ];
    for (input, expected) in cases {
        check_fixed(input, expected)?;
    }
    check_million_a()?;
    check_exhaustion()?;
    let (admitted_backends, skipped_unadmitted_backends) = check_backends()?;

    Ok(AcceptanceReport {
        fixed_messages: 6,
        streaming_messages: 6,
        admitted_backends,
        skipped_unadmitted_backends,
    })
}

fn check_fixed(input: &[u8], expected: &[u8; 64]) -> Result<(), AcceptanceError> {
    let reusable = sha256(input).map_err(|_| AcceptanceError::DigestMismatch)?;
    if !matches_hex(&reusable, expected) {
        return Err(AcceptanceError::DigestMismatch);
    }
    let composition = crypto_sha256(input).map_err(|_| AcceptanceError::FacadeMismatch)?;
    if composition != reusable {
        return Err(AcceptanceError::FacadeMismatch);
    }

    let mut reusable_stream = Sha256::new();
    let mut composition_stream = CryptoSha256::new();
    update_irregular(&mut reusable_stream, input)?;
    update_crypto_irregular(&mut composition_stream, input)?;
    if reusable_stream.finalize() != reusable || composition_stream.finalize() != reusable {
        return Err(AcceptanceError::StreamingMismatch);
    }
    Ok(())
}

fn check_million_a() -> Result<(), AcceptanceError> {
    let mut reusable = Sha256::new();
    let mut composition = CryptoSha256::new();
    for _ in 0..1_000 {
        reusable
            .update(&THOUSAND_A)
            .map_err(|_| AcceptanceError::DigestMismatch)?;
        composition
            .update(&THOUSAND_A)
            .map_err(|_| AcceptanceError::FacadeMismatch)?;
    }
    let reusable = reusable.finalize();
    if !matches_hex(&reusable, MILLION_A_SHA256) || composition.finalize() != reusable {
        return Err(AcceptanceError::DigestMismatch);
    }
    Ok(())
}

fn update_irregular(state: &mut Sha256, mut input: &[u8]) -> Result<(), AcceptanceError> {
    for width in IRREGULAR_WIDTHS.iter().copied().cycle() {
        if input.is_empty() {
            break;
        }
        let take = core::cmp::min(width, input.len());
        let (chunk, remaining) = input.split_at(take);
        state
            .update(chunk)
            .map_err(|_| AcceptanceError::StreamingMismatch)?;
        input = remaining;
    }
    Ok(())
}

fn update_crypto_irregular(
    state: &mut CryptoSha256,
    mut input: &[u8],
) -> Result<(), AcceptanceError> {
    for width in IRREGULAR_WIDTHS.iter().copied().cycle() {
        if input.is_empty() {
            break;
        }
        let take = core::cmp::min(width, input.len());
        let (chunk, remaining) = input.split_at(take);
        state
            .update(chunk)
            .map_err(|_| AcceptanceError::FacadeMismatch)?;
        input = remaining;
    }
    Ok(())
}

fn check_exhaustion() -> Result<(), AcceptanceError> {
    let mut state = Sha256::new();
    if state
        .check_additional_bytes(Sha256::MAX_MESSAGE_BYTES)
        .is_err()
        || state.check_additional_bytes(Sha256::MAX_MESSAGE_BYTES + 1)
            != Err(Sha256Error::MessageTooLong)
        || state.message_bytes() != 0
    {
        return Err(AcceptanceError::ExhaustionMismatch);
    }
    state
        .update(b"abc")
        .map_err(|_| AcceptanceError::ExhaustionMismatch)?;
    if state
        .check_additional_bytes(Sha256::MAX_MESSAGE_BYTES - 3)
        .is_err()
        || state.check_additional_bytes(Sha256::MAX_MESSAGE_BYTES - 2)
            != Err(Sha256Error::MessageTooLong)
        || state.message_bytes() != 3
    {
        return Err(AcceptanceError::ExhaustionMismatch);
    }
    Ok(())
}

fn check_backends() -> Result<(usize, usize), AcceptanceError> {
    let identities = [
        Sha256Backend::X86Sha,
        Sha256Backend::Aarch64Sha2,
        Sha256Backend::RiscVScalarCrypto,
    ];
    let mut admitted = 0_usize;
    let mut skipped = 0_usize;
    for backend in identities {
        if backend.is_admitted() {
            admitted = admitted.saturating_add(1);
        } else {
            skipped = skipped.saturating_add(1);
        }
    }
    if admitted != 0 || skipped != 3 || Sha256BackendSession::for_compiled_target().is_some() {
        return Err(AcceptanceError::BackendReportMismatch);
    }

    let _accelerated_public_entry = sha256_with_backend;
    Ok((admitted, skipped))
}

fn matches_hex(digest: &Sha256Digest, expected: &[u8; 64]) -> bool {
    digest
        .as_bytes()
        .iter()
        .zip(expected.chunks_exact(2))
        .all(|(actual, pair)| match pair {
            [high, low] => {
                let high = nibble(*high);
                let low = nibble(*low);
                high < 16 && low < 16 && *actual == high.saturating_mul(16).saturating_add(low)
            }
            _ => false,
        })
}

const fn nibble(byte: u8) -> u8 {
    match byte {
        b'0'..=b'9' => byte - b'0',
        b'a'..=b'f' => byte - b'a' + 10,
        _ => 0xff,
    }
}

#[cfg(test)]
mod tests {
    use super::{AcceptanceReport, run};

    #[test]
    fn public_acceptance_is_complete() {
        assert_eq!(
            run(),
            Ok(AcceptanceReport {
                fixed_messages: 6,
                streaming_messages: 6,
                admitted_backends: 0,
                skipped_unadmitted_backends: 3,
            })
        );
    }
}
