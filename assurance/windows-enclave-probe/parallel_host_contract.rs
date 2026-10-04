//! Typed host contract under test; not yet exported from a shipping crate.
//! Caller buffers stay outside the enclave. Shapes are public metadata; borrowed
//! input is not copied or inspected here. The enclave checks canonical tail bits
//! after copying. Explicit public declassification permits ordinary output
//! staging; it does not erase caller input or make this a secret-output API.
#![forbid(unsafe_code)]
use crate::{Error, ImagePolicy, adapter};
use brynja_hash_sha2::PublicDeclassification;
use core::marker::PhantomData;
use std::path::Path;

/// Exact ParallelHash identity, including fixed versus XOF domain separation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    ParallelHash128,
    ParallelHash256,
    ParallelHashXof128,
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
}
/// Public B-byte leaf size and output bit length. At most 65,536 leaves.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    algorithm: Algorithm,
    block: u64,
    output_bits: usize,
}
impl Plan {
    /// B is 1..=1024 bytes; output is 0..=8192 bits for every identity.
    pub fn new(algorithm: Algorithm, block: u64, output_bits: usize) -> Result<Self, Error> {
        if !(1..=1024).contains(&block) || output_bits > 8192 {
            return Err(Error::Bounds);
        }
        Ok(Self {
            algorithm,
            block,
            output_bits,
        })
    }
    /// Exact caller output width, including a partially used final byte.
    pub fn output_bytes(self) -> usize {
        self.output_bits.div_ceil(8)
    }
}
/// Borrowed low-bit-first input; no content-dependent host validation or copying.
pub struct Part<'a> {
    bytes: &'a [u8],
    bits: u64,
}
impl<'a> Part<'a> {
    pub fn bytes(bytes: &'a [u8]) -> Result<Self, Error> {
        Self::bits(bytes, if bytes.is_empty() { 0 } else { 8 })
    }
    /// Nonempty input uses 1..=8 low-order bits of its final byte; empty uses 0.
    /// Noncanonical high bits reject inside the enclave, not in this constructor.
    pub fn bits(bytes: &'a [u8], last: u8) -> Result<Self, Error> {
        let bits = shape(bytes.len(), last)?;
        Ok(Self { bytes, bits })
    }
    fn address(&self) -> Result<u64, Error> {
        if self.bits == 0 {
            return Ok(0);
        }
        let start = self.bytes.as_ptr() as usize;
        start.checked_add(self.bytes.len()).ok_or(Error::Bounds)?;
        u64::try_from(start).map_err(|_| Error::Bounds)
    }
}
fn shape(length: usize, last: u8) -> Result<u64, Error> {
    if length == 0 {
        return if last == 0 { Ok(0) } else { Err(Error::Bounds) };
    }
    if !(1..=8).contains(&last) {
        return Err(Error::Bounds);
    }
    u64::try_from(length.checked_sub(1).ok_or(Error::Bounds)?)
        .ok()
        .and_then(|n| n.checked_mul(8))
        .and_then(|n| n.checked_add(u64::from(last)))
        .ok_or(Error::Bounds)
}
/// Immutable borrows are held through the root call and every worker join.
pub struct Input<'a> {
    message: Part<'a>,
    custom: Part<'a>,
}
impl<'a> Input<'a> {
    pub fn new(message: Part<'a>, customization: Part<'a>) -> Self {
        Self {
            message,
            custom: customization,
        }
    }
}
pub(crate) struct Request<'a> {
    plan: Plan,
    input: Input<'a>,
}
impl Request<'_> {
    fn validate(&self) -> Result<(), Error> {
        let maximum = self
            .plan
            .block
            .checked_mul(8)
            .and_then(|n| n.checked_mul(65536))
            .ok_or(Error::Bounds)?;
        if self.input.message.bits > maximum || self.input.custom.bits > 8192 {
            return Err(Error::Bounds);
        }
        Ok(())
    }
    // Only the synchronous internal transport may encode borrowed addresses.
    // No pointer, raw header, fault setting or caller callback is publicly exposed.
    pub(crate) fn header(&self) -> Result<[u64; 16], Error> {
        self.validate()?;
        Ok([
            0x4252594e50485749,
            1,
            self.plan.algorithm.wire(),
            self.plan.block,
            self.input.message.bits,
            self.input.custom.bits,
            u64::try_from(self.plan.output_bits).map_err(|_| Error::Bounds)?,
            self.input.message.address()?,
            self.input.custom.address()?,
            1,
            0,
            0,
            0,
            0,
            0,
            0,
        ])
    }
}
pub(crate) trait Channel {
    // Must return only after all borrowed entries have joined; no detached work.
    fn execute(&mut self, request: &Request<'_>, output: &mut [u8; 1024]) -> Result<(), Error>;
    fn settled(&self) -> Result<(), Error>;
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Ready,
    Complete,
    Quarantined,
}
struct Owner<T: Channel> {
    channel: T,
    state: State,
    thread_bound: PhantomData<*mut ()>,
}
impl<T: Channel> Owner<T> {
    fn new(channel: T) -> Self {
        Self {
            channel,
            state: State::Ready,
            thread_bound: PhantomData,
        }
    }
    fn digest_public(
        &mut self,
        plan: Plan,
        input: Input<'_>,
        output: &mut [u8],
        _: PublicDeclassification,
    ) -> Result<(), Error> {
        if self.state != State::Ready {
            return Err(Error::Quarantined);
        }
        let request = Request { plan, input };
        request.validate()?;
        if output.len() != plan.output_bytes() {
            return Err(Error::Bounds);
        }
        // Preflight errors do not enter the enclave; once entered, any error or
        // recoverable unwind is terminal. Fatal abort cannot run Drop cleanup.
        self.state = State::Quarantined;
        let mut public = [0; 1024];
        let result = self.channel.execute(&request, &mut public);
        self.channel.settled()?; // mandatory even when the operation failed
        result?;
        let ready = public.get(..output.len()).ok_or(Error::Protocol)?;
        let remainder = plan.output_bits % 8;
        if remainder != 0 && ready.last().is_none_or(|b| b >> remainder != 0) {
            return Err(Error::Protocol);
        }
        output.copy_from_slice(ready);
        self.state = State::Complete;
        Ok(())
    }
}
/// One operation per pinned image, bound to its opening thread. No raw authority,
/// secret-output slice, application callback or production development fallback.
pub struct Session(Owner<adapter::Enclave>);
impl Session {
    /// Require the exact reviewed five-thread AVX2 image and production signature.
    /// No fallback. Image qualification and CPU/deployment guarantees remain the
    /// application publisher's responsibility; unsupported platforms reject.
    pub fn open_avx2(path: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self::from_transport(adapter::Enclave::open(
            path, policy, false,
        )?))
    }
    pub(crate) fn from_transport(channel: adapter::Enclave) -> Self {
        Self(Owner::new(channel))
    }
    pub fn state(&self) -> State {
        self.0.state
    }
    /// Explicitly declassify the final result. Caller destination is unchanged on
    /// error or unwind. A successful operation consumes this image's single use.
    /// Partial final output bits must be canonical; no host masking hides errors.
    pub fn digest_public(
        &mut self,
        plan: Plan,
        input: Input<'_>,
        output: &mut [u8],
        decision: PublicDeclassification,
    ) -> Result<(), Error> {
        self.0.digest_public(plan, input, output, decision)
    }
}
#[cfg(test)]
#[path = "parallel_host_contract_tests.rs"]
mod tests;
