//! Sequential SHA-2 batching: scalar version ten or opt-in SHA-NI version nineteen.
//! Eight public plan slots retain digests until the entire plan is sealed.
//! Inactive slots and unused digest suffixes export as zero. This is not SIMD
//! or parallel execution. SHA-NI supports only SHA-224/256; wider plans reject.
//! Caller input remains outside enclave protection.
//! Construction requires production image trust; no portable fallback exists.
//! Dropped unfinished handles quarantine; fatal abort is outside Drop cleanup.
//!
//! ```no_run
//! use brynja_crypto_cpu_std::windows_enclave::{sha2_batch::{Session, Plan, Algorithm}, Error, PublicDeclassification};
//! # fn example(session: &mut Session) -> Result<(), Error> {
//! let plan = Plan::new([Some(Algorithm::SHA256), None, None, None, None, None, None, None])?;
//! let mut batch = session.batch(plan, 3)?;
//! let mut item = batch.item()?;
//! item.update(b"abc")?;
//! item.finish()?;
//! let mut public = [0; 512];
//! batch.seal()?.declassify(&mut public, PublicDeclassification::acknowledge())?;
//! # Ok(()) }
//! ```
pub use super::sha2::Algorithm;
use super::sha2_batch_wire::Request;
use super::{Error, ImagePolicy, PublicDeclassification, State};
use core::marker::PhantomData;
use std::path::Path;
mod item;
mod transport;
pub use item::Item;
use transport::{Channel, Transport};

/// Public algorithm plan. `None` is inactive, not an empty message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan([Option<Algorithm>; 8]);
impl Plan {
    /// At least one slot must be active. Active slots execute in increasing order.
    pub fn new(slots: [Option<Algorithm>; 8]) -> Result<Self, Error> {
        if slots.iter().all(Option::is_none) {
            return Err(Error::Bounds);
        }
        Ok(Self(slots))
    }
    /// Public plan only; never private message lengths or intermediate state.
    #[must_use]
    pub fn slots(self) -> [Option<Algorithm>; 8] {
        self.0
    }
    fn wire(self) -> [u64; 8] {
        self.0.map(|a| a.map_or(0, Algorithm::wire))
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
/// Thread-bound owning batch session. No callbacks, raw authority or host secret outputs.
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Session>();\n```"]
pub struct Session(Owner<Transport>);
impl Session {
    /// Requires a reviewed version-ten image and production signature.
    pub fn open(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Owner {
            transport: Transport::open(location, policy)?,
            state: State::Ready,
            sequence: 0,
            thread_bound: PhantomData,
        }))
    }
    /// Explicitly select a reviewed version-nineteen SHA-NI batch enclave image.
    ///
    /// Requires `strict-sha2-acceleration`, production image trust and the full
    /// compiled SHA/SSE2/AVX/AVX2 CPU/OS bundle. Only SHA-224/256 plans are accepted;
    /// wide/general SHA-512 plans fail closed and quarantine the session.
    /// Scalar `open` remains unchanged. Slots execute sequentially, not as
    /// independent-message SIMD or multicore work. Caller input is not protected
    /// by this owner. Development execution is not production qualification.
    #[cfg(feature = "strict-sha2-acceleration")]
    pub fn open_sha_ni(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Owner {
            transport: Transport::open_sha_ni(location, policy)?,
            state: State::Ready,
            sequence: 0,
            thread_bound: PhantomData,
        }))
    }
    /// Public lifecycle only.
    #[must_use]
    pub fn state(&self) -> State {
        self.0.state
    }
    /// Begin one batch. The public byte budget counts supplied bytes, including
    /// the byte holding a partial final tail; it is not a compression-work budget.
    pub fn batch(&mut self, plan: Plan, max_input_bytes: u64) -> Result<Batch<'_>, Error> {
        match self.0.state {
            State::Ready => (),
            State::Busy => return Err(Error::Busy),
            _ => return Err(Error::Quarantined),
        }
        self.0.issue(
            Request {
                op: 80,
                plan: plan.wire(),
                budget: max_input_bytes,
                ..Request::default()
            },
            &[],
            None,
        )?;
        Ok(Batch(Loan {
            session: self,
            plan,
            next: 0,
            item_open: false,
            active: true,
        }))
    }
    /// Destroy even forgotten handles; report uncertain release instead of fallback.
    pub fn close(&mut self) -> Result<(), Error> {
        self.0.close()
    }
}
struct Loan<'a> {
    session: &'a mut Session,
    plan: Plan,
    next: usize,
    item_open: bool,
    active: bool,
}
impl Loan<'_> {
    fn next_slot(&self) -> Option<usize> {
        self.plan
            .0
            .iter()
            .enumerate()
            .skip(self.next)
            .find_map(|(slot, a)| a.map(|_| slot))
    }
    fn cancel(mut self) -> Result<(), Error> {
        self.session.0.issue(
            Request {
                op: 86,
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
/// Exclusive plan builder. Forgotten item writers cannot be implicitly completed.
#[must_use = "seal or cancel the batch"]
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Batch<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Batch<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Batch<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Batch<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Batch<'static>>();\n```"]
pub struct Batch<'a>(Loan<'a>);
impl<'a> Batch<'a> {
    /// Start the next active slot, in public plan order.
    pub fn item(&mut self) -> Result<Item<'_, 'a>, Error> {
        if self.0.session.state() == State::Quarantined {
            return Err(Error::Quarantined);
        }
        if self.0.item_open {
            return Err(Error::Busy);
        }
        let slot = self.0.next_slot().ok_or(Error::Bounds)?;
        self.0.item_open = true;
        self.0.session.0.issue(
            Request {
                op: 81,
                slot,
                ..Request::default()
            },
            &[],
            None,
        )?;
        Ok(Item {
            batch: self,
            slot,
            complete: false,
        })
    }
    /// Complete the entire plan before making any result exportable.
    pub fn seal(self) -> Result<Retained<'a>, Error> {
        if self.0.session.state() == State::Quarantined {
            return Err(Error::Quarantined);
        }
        if self.0.item_open || self.0.next_slot().is_some() {
            return Err(Error::Bounds);
        }
        self.0.session.0.issue(
            Request {
                op: 84,
                ..Request::default()
            },
            &[],
            None,
        )?;
        Ok(Retained(self.0))
    }
    /// Clear all progress, including a forgotten item writer, without export.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
}
/// Eight retained digest slots. No secret slice, cloning or partial batch export.
#[must_use = "declassify or cancel the retained batch"]
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha2_batch::Retained<'static>>();\n```"]
pub struct Retained<'a>(Loan<'a>);
impl Retained<'_> {
    /// Public plan describing the fixed 64-byte slots.
    #[must_use]
    pub fn plan(&self) -> Plan {
        self.0.plan
    }
    /// Export all eight 64-byte slots transactionally. Only each algorithm's
    /// public output width is populated; inactive slots and suffixes are zero.
    /// General SHA-512/t uses canonical MSB-first final output bits.
    pub fn declassify(
        mut self,
        destination: &mut [u8; 512],
        _authority: PublicDeclassification,
    ) -> Result<(), Error> {
        let mut public = [0; 512];
        self.0.session.0.issue(
            Request {
                op: 85,
                plan: self.0.plan.wire(),
                ..Request::default()
            },
            &[],
            Some(&mut public),
        )?;
        destination.copy_from_slice(&public);
        self.0.session.0.state = State::Ready;
        self.0.active = false;
        Ok(())
    }
    /// Clear the complete batch without exporting it.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
}
#[cfg(test)]
mod tests;
