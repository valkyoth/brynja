//! Sealed compile-time identities for caller-owned workspace arenas.

/// A byte-storage domain in a caller-owned workspace.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
#[non_exhaustive]
pub enum ArenaKind {
    /// Secret and secret-derived working bytes.
    Secret,
    /// Decrypted or pre-encryption application bytes.
    Plaintext,
    /// Canonical protocol transcript bytes.
    Transcript,
    /// Certificate and trust-chain working bytes.
    Certificate,
    /// Encoded protocol output bytes.
    Output,
}

impl ArenaKind {
    /// Every arena kind in its fixed workspace partition order.
    pub const ALL: [Self; 5] = [
        Self::Secret,
        Self::Plaintext,
        Self::Transcript,
        Self::Certificate,
        Self::Output,
    ];
}

mod sealed {
    pub trait Sealed {}
}

/// A sealed compile-time workspace arena identity.
///
/// Only Brynja's five marker types implement this trait. This makes named
/// simultaneous arena borrows different Rust types and prevents accidental
/// swapping between storage domains.
pub trait ArenaDomain: sealed::Sealed {
    /// The corresponding runtime identity.
    const KIND: ArenaKind;
}

/// Compile-time identity of storage reserved for future secret owners.
///
/// This marker classifies bytes but does not provide secret ownership,
/// initialization, erasure, or destruction. Sensitive use remains prohibited
/// until the separately reviewed lifetime and zeroization contracts exist.
pub enum SecretDomain {}

/// Compile-time identity of a plaintext arena.
pub enum PlaintextDomain {}

/// Compile-time identity of a transcript arena.
pub enum TranscriptDomain {}

/// Compile-time identity of a certificate and trust-chain arena.
///
/// This domain is not private-key storage. Private-key material requires the
/// future secret-owner contract rather than a certificate-arena allocation.
pub enum CertificateDomain {}

/// Compile-time identity of an output arena.
pub enum OutputDomain {}

macro_rules! arena_domain {
    ($domain:ty, $kind:expr) => {
        impl sealed::Sealed for $domain {}

        impl ArenaDomain for $domain {
            const KIND: ArenaKind = $kind;
        }
    };
}

arena_domain!(SecretDomain, ArenaKind::Secret);
arena_domain!(PlaintextDomain, ArenaKind::Plaintext);
arena_domain!(TranscriptDomain, ArenaKind::Transcript);
arena_domain!(CertificateDomain, ArenaKind::Certificate);
arena_domain!(OutputDomain, ArenaKind::Output);
