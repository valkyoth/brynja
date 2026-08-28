//! Small algorithm-independent interfaces for fixed-output hashes and XOFs.
//!
//! This crate defines interfaces only. It contains no hash implementation,
//! algorithm identifier, allocation, I/O, runtime dispatch, or protocol code.

#![no_std]

/// Incremental byte input for a hash computation.
///
/// Implementations must reject an update before changing observable state when
/// accepting its bytes would exceed the algorithm's message-length domain.
pub trait Update {
    /// Closed update failure type.
    type Error;

    /// Absorbs the complete byte slice or leaves the state unchanged.
    fn update(&mut self, input: &[u8]) -> Result<(), Self::Error>;
}

/// A hash state that produces one fixed-size digest and is consumed by doing so.
pub trait FixedOutput: Update {
    /// Algorithm-specific digest value.
    type Output: AsRef<[u8]>;

    /// Consumes the state and returns the digest.
    fn finalize(self) -> Self::Output;
}

/// A hash state that becomes a distinct extendable-output reader.
///
/// Consuming finalization makes absorbing after the first output byte
/// structurally impossible.
pub trait ExtendableOutput: Update {
    /// Algorithm-specific reader returned after domain-separated finalization.
    type Reader: XofReader;

    /// Consumes the absorbing state and returns its output reader.
    fn finalize_xof(self) -> Self::Reader;
}

/// Incremental caller-owned output from an extendable-output function.
pub trait XofReader {
    /// Closed output failure type.
    type Error;

    /// Fills the complete output slice or rejects it before changing the
    /// reader or caller-owned output.
    fn squeeze(&mut self, output: &mut [u8]) -> Result<(), Self::Error>;
}
