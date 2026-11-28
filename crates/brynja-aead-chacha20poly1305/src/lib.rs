//! Portable RFC 8439 authenticated encryption with 96-bit nonces and full tags.
//! Allocate a disjoint nonce range per sending key, including across restarts.
//! Opening authenticates the supplied ciphertext before decrypting it; it cannot
//! determine whether an authenticated message is fresh. Keys are caller-owned.
//! Counter capacity is not a traffic allowance. Apply the protocol's record,
//! byte and failed-authentication limits across its specified key/connection
//! scope. Bound untrusted AAD and payload lengths before allocating scratch:
//! processing takes work proportional to their combined length.
//!
//! Partially overlapping input/output is not representable by the safe API:
//!
//! ```compile_fail,E0502
//! use brynja_aead_chacha20poly1305::Sealer;
//! fn overlap(sender: &mut Sealer<'_>, data: &mut [u8; 5], scratch: &mut [u8; 4]) {
//!     let _ = sender.seal(b"", &data[..4], &mut data[1..], scratch);
//! }
//! ```
#![no_std]
#![forbid(unsafe_code)]

#[cfg(all(
    feature = "chacha20poly1305-x86",
    target_arch = "x86_64",
    target_os = "linux",
    target_feature = "sse2"
))]
pub mod execution;

#[cfg(test)]
mod interruptions;
mod message;
#[cfg(kani)]
mod proofs;
#[cfg(test)]
mod rfc_vectors;
#[cfg(test)]
mod tests;
use message::Buffers;

/// A public, value-free admission or operation failure.
/// Match with a wildcard so new failure categories can be added.
///
/// ```compile_fail,E0004
/// use brynja_aead_chacha20poly1305::Error;
/// fn label(e: Error) -> u8 {
///     match e { Error::Length => 0, Error::Exhausted => 1,
///               Error::Authentication => 2, Error::Invariant => 3 }
/// }
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Invalid reservation, incompatible buffer sizes, or unrepresentable frame.
    Length,
    /// No unused invocation remains in this sender's allocation.
    Exhausted,
    /// The received message failed full-tag authentication.
    Authentication,
    /// A previously admitted primitive operation unexpectedly failed.
    Invariant,
}

/// A forward-only sender borrowing the key. Cannot be cloned or rewound.
/// Release of this owner does not release unused nonces for reuse.
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use brynja_aead_chacha20poly1305::{Sealer, Error};
/// fn discard(key: &[u8; 32]) -> Result<(), Error> {
///     Sealer::from_reserved_range(key, [0; 4], 0, 1)?;
///     Ok(())
/// }
/// ```
#[must_use]
pub struct Sealer<'k> {
    key: &'k [u8; 32],
    prefix: [u8; 4],
    counters: core::ops::RangeInclusive<u64>,
}

impl<'k> Sealer<'k> {
    /// Adopt an already reserved, nonempty range. The wire nonce is
    /// `prefix || counter.to_be_bytes()`. Uniqueness across all uses of this
    /// key (including other APIs and processes) is the caller's responsibility.
    pub fn from_reserved_range(
        key: &'k [u8; 32],
        prefix: [u8; 4],
        first: u64,
        count: u64,
    ) -> Result<Self, Error> {
        let last = first
            .checked_add(count.checked_sub(1).ok_or(Error::Length)?)
            .ok_or(Error::Length)?;
        Ok(Self {
            key,
            prefix,
            counters: first..=last,
        })
    }

    /// Seal into a disjoint output using equally sized scratch. Returns nonce
    /// and full tag. Invalid lengths do not consume a nonce or touch buffers.
    pub fn seal(
        &mut self,
        aad: &[u8],
        input: &[u8],
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<([u8; 12], [u8; 16]), Error> {
        self.send(aad, Buffers::Separate(input, output), scratch)
    }

    /// Replace plaintext only after the entire operation succeeds.
    pub fn seal_in_place(
        &mut self,
        aad: &[u8],
        data: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<([u8; 12], [u8; 16]), Error> {
        self.send(aad, Buffers::InPlace(data), scratch)
    }

    fn send(
        &mut self,
        aad: &[u8],
        io: Buffers<'_>,
        scratch: &mut [u8],
    ) -> Result<([u8; 12], [u8; 16]), Error> {
        let frame = io.admit(aad, scratch)?;
        let nonce = self.take_nonce()?;
        io.transact(scratch, |input, work| {
            message::crypt(self.key, nonce, input, work)?;
            let tag = frame.with_mac(self.key, nonce, aad, work, |mac| Ok(mac.finalize()))?;
            Ok((nonce, tag))
        })
    }

    fn take_nonce(&mut self) -> Result<[u8; 12], Error> {
        let counter = self.counters.next().ok_or(Error::Exhausted)?;
        let mut nonce = [0; 12];
        let (prefix, suffix) = nonce.split_at_mut(4);
        prefix.copy_from_slice(&self.prefix);
        suffix.copy_from_slice(&counter.to_be_bytes());
        Ok(nonce)
    }
}

/// A receive-only owner. Does not reserve nonces or enforce replay policy.
///
/// ```compile_fail
/// #![deny(unused_must_use)]
/// use brynja_aead_chacha20poly1305::Opener;
/// fn discard(key: &[u8; 32]) { Opener::new(key); }
/// ```
#[must_use]
pub struct Opener<'k>(&'k [u8; 32]);

impl<'k> Opener<'k> {
    /// Borrow the caller's key without copying or taking ownership of it.
    pub fn new(key: &'k [u8; 32]) -> Self {
        Self(key)
    }

    /// Authenticate, then decrypt into disjoint output. Output is unchanged on
    /// rejection; admitted scratch is cleared even on authentication failure.
    pub fn open(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        tag: &[u8; 16],
        input: &[u8],
        output: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<(), Error> {
        self.receive(nonce, aad, tag, Buffers::Separate(input, output), scratch)
    }

    /// Authenticate, then replace ciphertext with plaintext on success only.
    pub fn open_in_place(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        tag: &[u8; 16],
        data: &mut [u8],
        scratch: &mut [u8],
    ) -> Result<(), Error> {
        self.receive(nonce, aad, tag, Buffers::InPlace(data), scratch)
    }

    fn receive(
        &self,
        nonce: [u8; 12],
        aad: &[u8],
        tag: &[u8; 16],
        io: Buffers<'_>,
        scratch: &mut [u8],
    ) -> Result<(), Error> {
        let frame = io.admit(aad, scratch)?;
        io.transact(scratch, |input, work| {
            frame.with_mac(self.0, nonce, aad, input, |mac| {
                mac.verify(tag).map_err(|_| Error::Authentication)
            })?;
            message::crypt(self.0, nonce, input, work)
        })
    }
}
