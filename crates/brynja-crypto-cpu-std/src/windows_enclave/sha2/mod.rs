//! Retained enclave SHA-2 streaming, using the separate version-six worker.
//!
//! All six named identities and every valid general SHA-512/t parameter are
//! supported by this protocol. Worker arithmetic is scalar; this interface does
//! not imply SIMD/hardware qualification. A version-four SHA-256 image is not
//! compatible. A reviewed image policy and production signature are mandatory.
//! Caller input remains outside protected storage; no secret output slice or
//! generic caller closure is exposed. Declassification is deliberate.
use super::{Error, ImagePolicy, PublicDeclassification, State};
use core::marker::PhantomData;
use std::path::Path;
mod algorithm;
mod transport;
pub use algorithm::Algorithm;
use transport::{Channel, Transport};

struct Owner<T: Channel> {
    transport: T,
    state: State,
    sequence: u64,
    thread_bound: PhantomData<*mut ()>,
}
impl<T: Channel> Owner<T> {
    fn issue(
        &mut self,
        op: usize,
        algorithm: Algorithm,
        input: &[u8],
        last: u8,
        output: Option<&mut [u8]>,
    ) -> Result<(), Error> {
        if matches!(self.state, State::Quarantined | State::Closed) {
            return Err(Error::Quarantined);
        }
        // Errors and unwind never authorize another operation.
        self.state = State::Quarantined;
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        self.transport.request(
            op,
            self.sequence,
            if matches!(op, 11 | 14 | 15) {
                algorithm.wire()
            } else {
                0
            },
            input,
            last,
            output,
        )?;
        self.state = if matches!(op, 15 | 16) {
            State::Ready
        } else {
            State::Busy
        };
        Ok(())
    }
    fn close(&mut self) -> Result<(), Error> {
        if self.state == State::Closed {
            return Ok(());
        }
        self.state = State::Quarantined;
        self.transport.close()?;
        self.state = State::Closed;
        Ok(())
    }
}
impl<T: Channel> Drop for Owner<T> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}

/// Thread-bound owning session. Construction never retries with weaker memory.
pub struct Session(Owner<Transport>);
impl Session {
    /// Load the matching reviewed version-six worker. Unsupported hosts reject.
    pub fn open(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Owner {
            transport: Transport::open(location, policy)?,
            state: State::Ready,
            sequence: 0,
            thread_bound: PhantomData,
        }))
    }
    /// Public lifecycle, not accumulated message length.
    #[must_use]
    pub fn state(&self) -> State {
        self.0.state
    }
    /// Begin one exclusive streaming computation.
    pub fn stream(&mut self, algorithm: Algorithm) -> Result<Stream<'_>, Error> {
        if self.0.state != State::Ready {
            return Err(if self.0.state == State::Busy {
                Error::Busy
            } else {
                Error::Quarantined
            });
        }
        self.0.issue(11, algorithm, &[], 0, None)?;
        Ok(Stream {
            session: self,
            algorithm,
            active: true,
        })
    }
    /// Clear any forgotten handle and close the enclave. Report uncertain release.
    pub fn close(&mut self) -> Result<(), Error> {
        self.0.close()
    }
}

/// Exclusive streaming handle. Dropping it without cancel/finalize quarantines.
/// No Send/Sync/Copy/Clone/Debug or public accumulated-length oracle.
#[must_use = "finalize or cancel the stream"]
pub struct Stream<'a> {
    session: &'a mut Session,
    algorithm: Algorithm,
    active: bool,
}
impl<'a> Stream<'a> {
    /// Absorb complete bytes through bounded snapshots; no total-message cap is
    /// imposed beyond the algorithm's checked length domain.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        if input.is_empty() {
            return self.session.0.issue(12, self.algorithm, &[], 0, None);
        }
        for chunk in input.chunks(1024) {
            self.session.0.issue(12, self.algorithm, chunk, 8, None)?;
        }
        Ok(())
    }
    /// Retain the digest inside the enclave without exporting secret bytes.
    pub fn finalize(self) -> Result<Digest<'a>, Error> {
        self.finalize_bits(&[], 0)
    }
    /// Include a canonical final MSB-first bit string. Empty input requires zero
    /// bits; otherwise the final byte has 1..=8 valid bits and unused bits zero.
    /// Invalid input terminates/quarantines this computation.
    pub fn finalize_bits(mut self, input: &[u8], last: u8) -> Result<Digest<'a>, Error> {
        if input.is_empty() {
            self.session
                .0
                .issue(13, self.algorithm, input, last, None)?;
        } else {
            let split = input.len().checked_sub(1).ok_or(Error::Bounds)?;
            self.update(input.get(..split).ok_or(Error::Bounds)?)?;
            self.session.0.issue(
                13,
                self.algorithm,
                input.get(split..).ok_or(Error::Bounds)?,
                last,
                None,
            )?;
        }
        Ok(Digest { stream: self })
    }
    /// Destroy enclave state without export; the session can then be reused.
    pub fn cancel(mut self) -> Result<(), Error> {
        self.session.0.issue(16, self.algorithm, &[], 0, None)?;
        self.active = false;
        Ok(())
    }
}
impl Drop for Stream<'_> {
    fn drop(&mut self) {
        if self.active {
            self.session.0.state = State::Quarantined;
        }
    }
}

/// A retained, noncopyable digest. Its algorithm is public; its bytes are not.
#[must_use = "declassify, rehash or cancel the retained digest"]
pub struct Digest<'a> {
    stream: Stream<'a>,
}
impl Digest<'_> {
    /// The exact public identity, including general SHA-512/t's bit count.
    #[must_use]
    pub fn algorithm(&self) -> Algorithm {
        self.stream.algorithm
    }
    /// Hash the exact retained bit string into another SHA-2 identity.
    pub fn rehash(mut self, algorithm: Algorithm) -> Result<Self, Error> {
        self.stream.session.0.issue(14, algorithm, &[], 0, None)?;
        self.stream.algorithm = algorithm;
        Ok(self)
    }
    /// Explicit public output, exact width and transactional on failure.
    pub fn declassify(
        mut self,
        destination: &mut [u8],
        _authority: PublicDeclassification,
    ) -> Result<(), Error> {
        let width = self.stream.algorithm.output_bytes();
        if destination.len() != width {
            self.stream.session.0.state = State::Quarantined;
            return Err(Error::Bounds);
        }
        let mut public = [0; 64];
        let stage = public.get_mut(..width).ok_or(Error::Bounds)?;
        self.stream
            .session
            .0
            .issue(15, self.stream.algorithm, &[], 0, Some(stage))?;
        destination.copy_from_slice(stage);
        self.stream.active = false;
        Ok(())
    }
    /// Destroy the result without exporting it.
    pub fn cancel(mut self) -> Result<(), Error> {
        self.stream
            .session
            .0
            .issue(16, self.stream.algorithm, &[], 0, None)?;
        self.stream.active = false;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
