//! Sequential ParallelHash/ParallelHashXOF in a scalar or opt-in AVX2 enclave.
//! Caller input is outside protected storage. Retained results have no host
//! secret-slice API. Requires strict-sha2 and strict-sha3; unsupported hosts fail
//! closed. AVX2 is single-state acceleration, not multicore leaf scheduling.
//! Production qualification remains separate.
//! Abandoned handles quarantine; fatal abort cannot run Drop cleanup.
use super::parallel_wire::Request;
use super::{Error, ImagePolicy, PublicDeclassification, State};
use core::marker::PhantomData;
use std::path::Path;
mod output;
mod stream;
mod transport;
pub use brynja_hash_sha3::Fips202BitString as Bits;
pub use output::{Finalized, Reader, Retained};
pub use stream::Stream;
use transport::{Channel, Transport};

/// Exact SP 800-185 identity. B and customization are declared separately.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// Fixed-output ParallelHash128.
    ParallelHash128,
    /// Fixed-output ParallelHash256.
    ParallelHash256,
    /// Extendable-output ParallelHashXOF128.
    ParallelHashXof128,
    /// Extendable-output ParallelHashXOF256.
    ParallelHashXof256,
}
impl Algorithm {
    fn wire(self) -> u64 {
        match self {
            Self::ParallelHash128 => 1,
            Self::ParallelHash256 => 2,
            Self::ParallelHashXof128 => 3,
            Self::ParallelHashXof256 => 4,
        }
    }
    fn fixed(self) -> bool {
        matches!(self, Self::ParallelHash128 | Self::ParallelHash256)
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
        if output.as_ref().map(|v| v.len()) != request.output_width() {
            return Err(Error::Bounds);
        }
        self.transport.request(request, input, output)?;
        self.state = State::Busy;
        Ok(())
    }
    fn simple(&mut self, op: usize) -> Result<(), Error> {
        self.issue(
            Request {
                op,
                ..Request::default()
            },
            &[],
            None,
        )
    }
    fn customization(&mut self, input: Bits<'_>) -> Result<(), Error> {
        let complete = input.bit_len() / 8;
        for chunk in input
            .as_bytes()
            .get(..complete)
            .ok_or(Error::Bounds)?
            .chunks(1024)
        {
            self.issue(
                Request {
                    op: 101,
                    last: 8,
                    ..Request::default()
                },
                chunk,
                None,
            )?;
        }
        if !input.is_byte_aligned() {
            self.issue(
                Request {
                    op: 101,
                    last: input.valid_bits_in_last_byte(),
                    ..Request::default()
                },
                input.as_bytes().get(complete..).ok_or(Error::Bounds)?,
                None,
            )?;
        }
        self.simple(102)
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

/// Owning thread-bound session; no application callbacks or raw authority.
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Session>();\n```"]
pub struct Session(Owner<Transport>);
impl Session {
    /// Explicitly select a reviewed version-eighteen AVX2 enclave image.
    /// Requires production image trust and the complete enclave CPU/OS bundle;
    /// rejection never retries the scalar route. Root and leaves execute
    /// sequentially using AVX2 Keccak, not independent-message SIMD or multicore.
    /// Caller inputs remain outside protected storage; current-image qualification
    /// and deployment guarantees are still required. Scalar `open` is unchanged.
    #[cfg(feature = "strict-sha3-acceleration")]
    pub fn open_avx2(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Owner {
            transport: Transport::open_avx2(location, policy)?,
            state: State::Ready,
            sequence: 0,
            thread_bound: PhantomData,
        }))
    }
    /// Requires production image trust, never development-signature fallback.
    pub fn open(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Owner {
            transport: Transport::open(location, policy)?,
            state: State::Ready,
            sequence: 0,
            thread_bound: PhantomData,
        }))
    }
    /// Public lifecycle only; no private accumulated-length or reader-position oracle.
    pub fn state(&self) -> State {
        self.0.state
    }
    /// Start a positive B-byte leaf stream. Budget counts supplied customization
    /// and message bytes, including partial bytes; B does not size an allocation.
    pub fn stream(
        &mut self,
        algorithm: Algorithm,
        block: u64,
        custom: Bits<'_>,
        budget: u64,
    ) -> Result<Stream<'_>, Error> {
        match self.0.state {
            State::Ready => (),
            State::Busy => return Err(Error::Busy),
            _ => return Err(Error::Quarantined),
        }
        self.0.issue(
            Request {
                op: 100,
                algorithm: algorithm.wire(),
                block,
                budget,
                custom_bits: u128::try_from(custom.bit_len()).map_err(|_| Error::Bounds)?,
                ..Request::default()
            },
            &[],
            None,
        )?;
        self.0.customization(custom)?;
        Ok(Stream(Loan {
            session: self,
            algorithm,
            active: true,
        }))
    }
    /// Destroy even forgotten handles; release only after confirmed cleanup.
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
        self.session.0.simple(107)?;
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
#[cfg(test)]
mod tests;
