//! SHA-3/SHAKE/cSHAKE with scalar-by-default enclave execution.
//! No enclave-private output is exposed as a host secret slice. Caller input
//! buffers remain outside protected storage. `Session::open_avx2` explicitly
//! selects the separate version-fourteen image with complete feature admission.
//! Production signing and platform qualification remain separate obligations.
//! Handles quarantine on abandonment/unwind; fatal abort cannot run Drop.
use super::sha3_wire::Request;
use super::{Error, ImagePolicy, PublicDeclassification, State};
use core::marker::PhantomData;
use std::path::Path;
mod output;
mod transport;
/// Canonical low-bit-first input, including N/S. Lengths are public metadata.
pub use brynja_hash_sha3::Fips202BitString as Bits;
pub use output::{Finalized, Reader, Retained};
use transport::{Channel, Transport};

/// Exact public function identity; customization is supplied separately.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// FIPS 202 SHA3-224.
    Sha3_224,
    /// FIPS 202 SHA3-256.
    Sha3_256,
    /// FIPS 202 SHA3-384.
    Sha3_384,
    /// FIPS 202 SHA3-512.
    Sha3_512,
    /// FIPS 202 SHAKE128.
    Shake128,
    /// FIPS 202 SHAKE256.
    Shake256,
    /// SP 800-185 cSHAKE128.
    Cshake128,
    /// SP 800-185 cSHAKE256.
    Cshake256,
}
impl Algorithm {
    pub(super) fn wire(self) -> u64 {
        match self {
            Self::Sha3_224 => 1,
            Self::Sha3_256 => 2,
            Self::Sha3_384 => 3,
            Self::Sha3_512 => 4,
            Self::Shake128 => 5,
            Self::Shake256 => 6,
            Self::Cshake128 => 7,
            Self::Cshake256 => 8,
        }
    }
    pub(super) fn width(self) -> Option<usize> {
        match self {
            Self::Sha3_224 => Some(28),
            Self::Sha3_256 => Some(32),
            Self::Sha3_384 => Some(48),
            Self::Sha3_512 => Some(64),
            _ => None,
        }
    }
}
struct Owner<T: Channel> {
    transport: T,
    state: State,
    sequence: u64,
    thread_bound: PhantomData<*mut ()>,
}
impl<T: Channel> Owner<T> {
    fn issue(
        &mut self,
        mut request: Request,
        input: &[u8],
        output: Option<&mut [u8]>,
    ) -> Result<(), Error> {
        if matches!(self.state, State::Quarantined | State::Closed) {
            return Err(Error::Quarantined);
        }
        self.state = State::Quarantined;
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        request.sequence = self.sequence;
        let _ = request.header(input)?;
        self.transport.request(request, input, output)?;
        self.state = State::Busy;
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
    fn chunks(&mut self, op: usize, input: Bits<'_>) -> Result<(), Error> {
        let complete = input.bit_len() / 8;
        for chunk in input
            .as_bytes()
            .get(..complete)
            .ok_or(Error::Bounds)?
            .chunks(1024)
        {
            self.issue(
                Request {
                    op,
                    last: 8,
                    ..Request::default()
                },
                chunk,
                None,
            )?;
        }
        if input.bit_len() % 8 != 0 {
            self.issue(
                Request {
                    op,
                    last: input.valid_bits_in_last_byte(),
                    ..Request::default()
                },
                input.as_bytes().get(complete..).ok_or(Error::Bounds)?,
                None,
            )?;
        }
        Ok(())
    }
    fn custom(
        &mut self,
        algorithm: Algorithm,
        name: Bits<'_>,
        custom: Bits<'_>,
    ) -> Result<(), Error> {
        if !matches!(algorithm, Algorithm::Cshake128 | Algorithm::Cshake256) {
            self.state = State::Quarantined;
            return Err(Error::Bounds);
        }
        self.issue(
            Request {
                op: 28,
                algorithm: algorithm.wire(),
                name_bits: u128::try_from(name.bit_len()).map_err(|_| Error::Bounds)?,
                custom_bits: u128::try_from(custom.bit_len()).map_err(|_| Error::Bounds)?,
                ..Request::default()
            },
            &[],
            None,
        )?;
        self.chunks(29, name)?;
        self.chunks(30, custom)?;
        self.issue(
            Request {
                op: 31,
                ..Request::default()
            },
            &[],
            None,
        )
    }
}
impl<T: Channel> Drop for Owner<T> {
    fn drop(&mut self) {
        let _ = self.close();
    }
}
/// Owning, thread-bound enclave session. Unsupported hosts fail closed.
pub struct Session(Owner<Transport>);
impl Session {
    /// Verify production trust and load the reviewed scalar version-seven worker.
    pub fn open(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Owner {
            transport: Transport::open(location, policy)?,
            state: State::Ready,
            sequence: 0,
            thread_bound: PhantomData,
        }))
    }
    /// Explicit AVX2 execution for all eight SHA-3/SHAKE/cSHAKE identities.
    /// Requires `strict-sha3-acceleration` (facade: `acceleration`), the reviewed
    /// version-fourteen image and mandatory production signature/import policy.
    /// Baseline enclave entry checks the complete AVX/AVX2 and OS vector-state
    /// bundle before any specialized Rust, including destruction. Missing image,
    /// platform or instruction support fails closed; never falls back to scalar.
    ///
    /// Development execution is not production qualification. Deployment must
    /// preserve these features across scheduling and migration; losing support
    /// rejects entry and cannot promise specialized cleanup. Fatal abort cannot
    /// run Drop. Caller buffers and application-created copies are not protected.
    #[cfg(feature = "strict-sha3-acceleration")]
    pub fn open_avx2(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Owner {
            transport: Transport::open_avx2(location, policy)?,
            state: State::Ready,
            sequence: 0,
            thread_bound: PhantomData,
        }))
    }
    /// Public lifecycle only, never accumulated message or reader position.
    #[must_use]
    pub fn state(&self) -> State {
        self.0.state
    }
    fn ready(&self) -> Result<(), Error> {
        match self.0.state {
            State::Ready => Ok(()),
            State::Busy => Err(Error::Busy),
            _ => Err(Error::Quarantined),
        }
    }
    /// Start a function with empty customization. cSHAKE then equals SHAKE.
    pub fn stream(&mut self, algorithm: Algorithm) -> Result<Stream<'_>, Error> {
        self.ready()?;
        self.0.issue(
            Request {
                op: 21,
                algorithm: algorithm.wire(),
                ..Request::default()
            },
            &[],
            None,
        )?;
        Ok(Stream(Loan {
            session: self,
            algorithm,
            active: true,
        }))
    }
    /// Start cSHAKE with arbitrary canonical N/S bit strings. Copy bounded
    /// snapshots; no complete setup buffer is allocated inside the enclave.
    pub fn customized(
        &mut self,
        algorithm: Algorithm,
        name: Bits<'_>,
        custom: Bits<'_>,
    ) -> Result<Stream<'_>, Error> {
        self.ready()?;
        self.0.custom(algorithm, name, custom)?;
        Ok(Stream(Loan {
            session: self,
            algorithm,
            active: true,
        }))
    }
    /// Destroy even forgotten handles and release only after confirmed cleanup.
    pub fn close(&mut self) -> Result<(), Error> {
        self.0.close()
    }
}
struct Loan<'a> {
    session: &'a mut Session,
    algorithm: Algorithm,
    active: bool,
}
impl Loan<'_> {
    fn cancel(mut self) -> Result<(), Error> {
        self.session.0.issue(
            Request {
                op: 26,
                ..Request::default()
            },
            &[],
            None,
        )?;
        self.session.0.state = State::Ready;
        self.active = false;
        Ok(())
    }
}
impl Drop for Loan<'_> {
    fn drop(&mut self) {
        if self.active {
            self.session.0.state = State::Quarantined;
        }
    }
}
/// Exclusive message loan; dropping it quarantines instead of authorizing reuse.
#[must_use = "finalize or cancel the stream"]
pub struct Stream<'a>(Loan<'a>);
impl<'a> Stream<'a> {
    /// Absorb bytes using bounded snapshots. Inputs/copies remain caller-owned.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        if input.is_empty() {
            return self.0.session.0.issue(
                Request {
                    op: 22,
                    ..Request::default()
                },
                &[],
                None,
            );
        }
        for chunk in input.chunks(1024) {
            self.0.session.0.issue(
                Request {
                    op: 22,
                    last: 8,
                    ..Request::default()
                },
                chunk,
                None,
            )?;
        }
        Ok(())
    }
    /// Finish without a tail; return a retained fixed digest or XOF reader.
    pub fn finalize(self) -> Result<Finalized<'a>, Error> {
        self.finalize_bits(Bits::new(&[], 0).map_err(|_| Error::Bounds)?)
    }
    /// Finish with a low-bit-first canonical tail, never SHA-2 bit packing.
    pub fn finalize_bits(mut self, input: Bits<'_>) -> Result<Finalized<'a>, Error> {
        let complete = input.bit_len() / 8;
        self.update(input.as_bytes().get(..complete).ok_or(Error::Bounds)?)?;
        let tail = input.as_bytes().get(complete..).ok_or(Error::Bounds)?;
        self.0.session.0.issue(
            Request {
                op: 23,
                last: if tail.is_empty() {
                    0
                } else {
                    input.valid_bits_in_last_byte()
                },
                ..Request::default()
            },
            tail,
            None,
        )?;
        Ok(output::finished(self.0))
    }
    /// Clear without exporting anything; successful cancellation permits reuse.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
}
#[cfg(test)]
mod tests;
