//! Bounded eight-message SHA-224/256 AVX2 execution inside Windows VBS.
//!
//! This distinct version-21 image requires AVX2 and OS vector support; it never
//! retries with scalar execution. Each lane supplies 64..=1024 bytes, including
//! at least one complete 64-byte block. This is not an unbounded streaming API.
//! SHA-224 and SHA-256 can be mixed; wide SHA-2 identities reject.
//! Caller input buffers remain ordinary host memory. Lengths, identities and
//! budget are public metadata. Only explicit declassification exports digests.
//! Production signature and reviewed image policy are mandatory; development
//! execution is not production-signing success or whole-image qualification.
pub use super::sha2::Algorithm;
use super::{Error, ImagePolicy, PublicDeclassification, State};
use core::marker::PhantomData;
use std::path::Path;
mod transport;
pub(in crate::windows_enclave) mod wire;
use transport::{Channel, Transport};
use wire::{CANCEL, DIGEST, EXPORT, Request};

/// Eight public identities in output order; wide SHA-2 identities are rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan([Algorithm; 8]);
impl Plan {
    /// Validate every identity before admitting a batch.
    pub fn new(algorithms: [Algorithm; 8]) -> Result<Self, Error> {
        for algorithm in algorithms {
            wire::identity(algorithm)?;
        }
        Ok(Self(algorithms))
    }
}
/// Borrowed caller input. This does not move caller storage into the enclave.
pub struct Input<'a> {
    bytes: &'a [u8],
    last: u8,
}
impl<'a> Input<'a> {
    /// Complete bytes. Bounds are checked by the session and again by the worker.
    #[must_use]
    pub const fn bytes(bytes: &'a [u8]) -> Self {
        Self { bytes, last: 8 }
    }
    /// Final byte contains `last` high-order bits (1..=8); unused bits must be
    /// zero. Canonical bits are checked only after enclave copying, not on host.
    #[must_use]
    pub const fn bits(bytes: &'a [u8], last: u8) -> Self {
        Self { bytes, last }
    }
}
fn empty() -> [Input<'static>; 8] {
    core::array::from_fn(|_| Input {
        bytes: &[],
        last: 0,
    })
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
        input: &[Input<'_>; 8],
        output: Option<&mut [u8; 256]>,
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
        input: [Input<'_>; 8],
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
    /// Require the reviewed version-21 AVX2 image and successful Windows trust.
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
    /// Compute eight independent messages and retain all results in the enclave.
    /// Budget covers lane blocks and padding/tails. Any
    /// computation failure or unwinding quarantines; panic=abort cannot run Drop.
    pub fn digest(
        &mut self,
        plan: Plan,
        input: [Input<'_>; 8],
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
    fn export(mut self, output: &mut [u8; 256]) -> Result<(), Error> {
        let mut public = [0; 256];
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
    /// Deliberately export public digests in eight 32-byte slots, plan order.
    /// SHA-224 digests are zero-padded to the fixed slot width.
    /// The caller destination remains unchanged on any reported error.
    pub fn declassify(
        self,
        output: &mut [u8; 256],
        _: PublicDeclassification,
    ) -> Result<(), Error> {
        self.0.export(output)
    }
    /// Discard all eight retained digests without copying them into host memory.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
}
#[cfg(test)]
mod tests;
