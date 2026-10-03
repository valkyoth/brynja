//! Bounded four-message SHA-3/SHAKE/cSHAKE AVX2 execution inside Windows VBS.
//!
//! Requires the distinct version-22 image; no scalar fallback. Each message,
//! function name and customization is bounded to 1024 bytes. Outputs are at most
//! 2048 bits per lane. This is not an unbounded streaming API.
//! Caller inputs remain ordinary host memory. Lengths, identities and budgets
//! are public metadata. Only explicit declassification exports results.
//! Production image trust is mandatory. Development execution does not establish
//! production signing, whole-image cleanup or Windows ARM64 qualification.
pub use super::sha3::Algorithm;
use super::{Error, ImagePolicy, PublicDeclassification, State};
use core::marker::PhantomData;
use std::path::Path;
mod transport;
pub(in crate::windows_enclave) mod wire;
use transport::{Channel, Transport};
use wire::{CANCEL, DIGEST, EXPORT, Request};

/// Public algorithm identity and output length for one lane.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Slot {
    /// SHA-3, SHAKE or cSHAKE identity.
    pub algorithm: Algorithm,
    /// Fixed SHA-3 size or 0..=2048 bits for SHAKE/cSHAKE.
    pub output_bits: usize,
}
/// Four public lane descriptions in retained-output order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan([Slot; 4]);
impl Plan {
    /// Validate all output lengths before admitting a batch.
    pub fn new(slots: [Slot; 4]) -> Result<Self, Error> {
        for slot in slots {
            if slot.output_bits > 2048
                || slot
                    .algorithm
                    .width()
                    .is_some_and(|n| n.checked_mul(8) != Some(slot.output_bits))
            {
                return Err(Error::Bounds);
            }
        }
        Ok(Self(slots))
    }
}
/// Borrowed low-bit-first field. No copying or content inspection on construction.
pub struct Part<'a> {
    bytes: &'a [u8],
    last: u8,
}
impl<'a> Part<'a> {
    /// Complete bytes, including canonical empty input.
    #[must_use]
    pub const fn bytes(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            last: if bytes.is_empty() { 0 } else { 8 },
        }
    }
    /// Last byte contains 1..=8 low-order valid bits; empty input requires zero.
    /// Unused high bits must be zero. The worker checks bytes after enclave copy.
    #[must_use]
    pub const fn bits(bytes: &'a [u8], last: u8) -> Self {
        Self { bytes, last }
    }
}
/// Three borrowed fields per lane. N/S must be empty outside cSHAKE.
pub struct Input<'a> {
    message: Part<'a>,
    name: Part<'a>,
    customization: Part<'a>,
}
impl<'a> Input<'a> {
    /// Message, function name and customization; all lengths are public metadata.
    #[must_use]
    pub const fn new(message: Part<'a>, name: Part<'a>, customization: Part<'a>) -> Self {
        Self {
            message,
            name,
            customization,
        }
    }
    /// Byte message with no function name or customization.
    #[must_use]
    pub const fn bytes(message: &'a [u8]) -> Self {
        Self::new(Part::bytes(message), Part::bytes(&[]), Part::bytes(&[]))
    }
}
fn empty() -> [Input<'static>; 4] {
    core::array::from_fn(|_| Input::bytes(&[]))
}
struct Owner<T: Channel> {
    transport: T,
    state: State,
    sequence: u64,
    thread_bound: PhantomData<*mut ()>,
}
impl<T: Channel> Owner<T> {
    fn new(transport: T) -> Self {
        Self {
            transport,
            state: State::Ready,
            sequence: 0,
            thread_bound: PhantomData,
        }
    }
    fn issue(
        &mut self,
        op: usize,
        plan: Plan,
        budget: u64,
        input: &[Input<'_>; 4],
        output: Option<&mut [u8; 1024]>,
    ) -> Result<(), Error> {
        if matches!(self.state, State::Quarantined | State::Closed) {
            return Err(Error::Quarantined);
        }
        self.state = State::Quarantined;
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Exhausted)?;
        let request = Request {
            op,
            sequence: self.sequence,
            budget,
            plan,
        };
        // Validate metadata without reading caller message bytes.
        request.header(input)?;
        self.transport.request(request, input, output)?;
        self.state = if op == DIGEST {
            State::Busy
        } else {
            State::Ready
        };
        Ok(())
    }
    fn digest(
        &mut self,
        plan: Plan,
        input: [Input<'_>; 4],
        budget: u64,
    ) -> Result<Lease<'_, T>, Error> {
        if self.state != State::Ready {
            return Err(if self.state == State::Busy {
                Error::Busy
            } else {
                Error::Quarantined
            });
        }
        self.issue(DIGEST, plan, budget, &input, None)?;
        Ok(Lease {
            owner: self,
            plan,
            active: true,
        })
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

/// Thread-bound session; no raw authority, secret output slice or caller callback.
pub struct Session(Owner<Transport>);
impl Session {
    /// Require the reviewed version-22 AVX2 image and successful Windows trust.
    /// Missing capabilities, wrong images and unsupported platforms reject.
    /// Revalidation is not a scheduler lock or a live VM-migration guarantee.
    pub fn open_avx2(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Owner::new(Transport::open_avx2(location, policy)?)))
    }
    /// Public lifecycle only; no query into private message state.
    #[must_use]
    pub fn state(&self) -> State {
        self.0.state
    }
    /// Compute four independent messages and retain all results in the enclave.
    /// Budget covers vector permutations and scalar tails, including N/S prefixes. Any
    /// computation failure or unwinding quarantines; panic=abort cannot run Drop.
    pub fn digest(
        &mut self,
        plan: Plan,
        input: [Input<'_>; 4],
        budget: u64,
    ) -> Result<Retained<'_>, Error> {
        Ok(Retained(self.0.digest(plan, input, budget)?))
    }
    /// Destroy retained state and close; report uncertain cleanup, never fallback.
    pub fn close(&mut self) -> Result<(), Error> {
        self.0.close()
    }
}

struct Lease<'a, T: Channel> {
    owner: &'a mut Owner<T>,
    plan: Plan,
    active: bool,
}
impl<T: Channel> Lease<'_, T> {
    fn export(mut self, output: &mut [u8; 1024]) -> Result<(), Error> {
        let mut public = [0; 1024];
        self.owner
            .issue(EXPORT, self.plan, 0, &empty(), Some(&mut public))?;
        output.copy_from_slice(&public);
        self.active = false;
        Ok(())
    }
    fn cancel(mut self) -> Result<(), Error> {
        self.owner.issue(CANCEL, self.plan, 0, &empty(), None)?;
        self.active = false;
        Ok(())
    }
}
impl<T: Channel> Drop for Lease<'_, T> {
    fn drop(&mut self) {
        if self.active {
            self.owner.state = State::Quarantined;
        }
    }
}
/// Exclusive affine result handle. Dropping without export/cancel quarantines;
/// forgetting it leaves the session busy until explicitly closed.
#[must_use = "declassify or cancel the retained result"]
pub struct Retained<'a>(Lease<'a, Transport>);
impl Retained<'_> {
    /// Deliberately export public results in four 256-byte slots, plan order.
    /// Short digests are zero-padded and partial final bytes canonically masked.
    /// The caller destination remains unchanged on any reported error.
    pub fn declassify(
        self,
        output: &mut [u8; 1024],
        _: PublicDeclassification,
    ) -> Result<(), Error> {
        self.0.export(output)
    }
    /// Discard all four retained digests without copying them into host memory.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
}
#[cfg(test)]
mod tests;
