//! Frozen package-external portable acceptance for the SP 800-185 family.

#![no_std]

mod cshake;
mod facades;
mod kmac;
mod parallelhash;
mod tuplehash;
mod vectors;

/// A closed portable-acceptance failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AcceptanceError {
    /// cSHAKE behavior or lifecycle differed.
    Cshake,
    /// KMAC or KMACXOF behavior or lifecycle differed.
    Kmac,
    /// TupleHash or TupleHashXOF behavior or lifecycle differed.
    TupleHash,
    /// ParallelHash or ParallelHashXOF behavior or lifecycle differed.
    ParallelHash,
    /// One public facade differed from its owning leaf package.
    Facade,
    /// A complete-family implementation claim differed.
    Claim,
}

/// Counts proven by the frozen v0.24.16 portable fixture.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AcceptanceReport {
    /// Named SP 800-185 function instances exercised.
    pub identities: usize,
    /// Official NIST example outputs checked.
    pub official_examples: usize,
    /// Distinct hardened identity profiles exercised.
    pub hardened_profiles: usize,
    /// Public package layers compared with owning leaves.
    pub public_layers: usize,
}

/// Runs the complete frozen portable SP 800-185 consumer contract.
pub fn run() -> Result<AcceptanceReport, AcceptanceError> {
    cshake::run()?;
    kmac::run()?;
    tuplehash::run()?;
    parallelhash::run()?;
    facades::run()?;
    if !brynja_hash_sha3::CSHAKE_IMPLEMENTED
        || !brynja_mac_kmac::KMAC_IMPLEMENTED
        || !brynja_hash_tuple::TUPLE_HASH_IMPLEMENTED
        || !brynja_hash_parallel::PARALLEL_HASH_IMPLEMENTED
    {
        return Err(AcceptanceError::Claim);
    }
    Ok(AcceptanceReport {
        identities: 14,
        official_examples: 14,
        hardened_profiles: 14,
        public_layers: 3,
    })
}

pub(crate) fn hex_eq(actual: &[u8], expected: &[u8]) -> bool {
    if actual.len().checked_mul(2) != Some(expected.len()) {
        return false;
    }
    actual
        .iter()
        .zip(expected.chunks_exact(2))
        .all(|(byte, pair)| hex(pair[0]).zip(hex(pair[1])) == Some((byte >> 4, byte & 0x0f)))
}

const fn hex(value: u8) -> Option<u8> {
    match value {
        b'0'..=b'9' => Some(value - b'0'),
        b'A'..=b'F' => Some(value - b'A' + 10),
        _ => None,
    }
}

pub(crate) fn sequence<const LENGTH: usize>(start: u8) -> [u8; LENGTH] {
    core::array::from_fn(|index| start.wrapping_add(u8::try_from(index).unwrap_or_default()))
}

#[cfg(test)]
mod tests {
    #[test]
    fn every_portable_sp800185_profile_passes_together() {
        assert_eq!(
            super::run(),
            Ok(super::AcceptanceReport {
                identities: 14,
                official_examples: 14,
                hardened_profiles: 14,
                public_layers: 3,
            })
        );
    }
}
