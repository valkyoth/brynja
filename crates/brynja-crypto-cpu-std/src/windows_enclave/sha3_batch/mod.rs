//! Sequential scalar SHA-3/SHAKE/cSHAKE batching through a separate version-eleven enclave.
//! Eight public slots share at most 1024 bytes until the whole plan is sealed.
//! Results are packed in plan order; unused output suffix bytes are zero. This is not SIMD
//! or parallel execution. Caller input remains outside enclave protection.
//! Construction requires production image trust; no portable fallback exists.
//! Dropped unfinished handles quarantine; fatal abort is outside Drop cleanup.
//!
//! ```no_run
//! use brynja_crypto_cpu_std::windows_enclave::{sha3_batch::{Session, Plan, Output, Algorithm}, Error, PublicDeclassification};
//! # fn example(session: &mut Session) -> Result<(), Error> {
//! let plan = Plan::new([Some(Output::new(Algorithm::Sha3_256, 32, 8)?), None, None, None, None, None, None, None])?;
//! let mut batch = session.batch(plan, 3)?;
//! let mut item = batch.item()?;
//! item.update(b"abc")?;
//! item.finish()?;
//! let mut public = [0; 1024];
//! batch.seal()?.declassify(&mut public, PublicDeclassification::acknowledge())?;
//! # Ok(()) }
//! ```
pub use super::sha3::{Algorithm, Bits};
mod plan;
use super::sha3_batch_wire::Request;
use super::{Error, ImagePolicy, PublicDeclassification, State};
use core::marker::PhantomData;
pub use plan::{Output, Plan};
use std::path::Path;
mod item;
mod transport;
pub use item::Item;
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
    fn setup_chunks(&mut self, op: usize, slot: usize, input: Bits<'_>) -> Result<(), Error> {
        let full = input.bit_len() / 8;
        for chunk in input
            .as_bytes()
            .get(..full)
            .ok_or(Error::Bounds)?
            .chunks(1024)
        {
            self.issue(
                Request {
                    op,
                    slot,
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
                    slot,
                    last: input.valid_bits_in_last_byte(),
                    ..Request::default()
                },
                input.as_bytes().get(full..).ok_or(Error::Bounds)?,
                None,
            )?;
        }
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
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Session>();\n```"]
pub struct Session(Owner<Transport>);
impl Session {
    /// Requires a reviewed version-eleven image and production signature.
    pub fn open(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Owner {
            transport: Transport::open(location, policy)?,
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
    /// Begin one batch. The public byte budget counts setup and message bytes, including
    /// the byte holding a partial final tail; it is not a compression-work budget.
    pub fn batch(&mut self, plan: Plan, max_input_bytes: u64) -> Result<Batch<'_>, Error> {
        match self.0.state {
            State::Ready => (),
            State::Busy => return Err(Error::Busy),
            _ => return Err(Error::Quarantined),
        }
        self.0.issue(
            Request {
                op: 90,
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
            .slots
            .iter()
            .enumerate()
            .skip(self.next)
            .find_map(|(slot, a)| a.map(|_| slot))
    }
    fn cancel(mut self) -> Result<(), Error> {
        self.session.0.issue(
            Request {
                op: 99,
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
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Batch<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Batch<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Batch<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Batch<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Batch<'static>>();\n```"]
pub struct Batch<'a>(Loan<'a>);
impl<'a> Batch<'a> {
    /// Start the next active slot without customization.
    pub fn item(&mut self) -> Result<Item<'_, 'a>, Error> {
        let empty = Bits::new(&[], 0).map_err(|_| Error::Bounds)?;
        self.item_custom(empty, empty)
    }
    /// Start the next slot with exact low-bit-first cSHAKE N/S. Nonempty N/S
    /// require a cSHAKE identity. These inputs and their lengths are caller-owned.
    pub fn item_custom(&mut self, name: Bits<'_>, custom: Bits<'_>) -> Result<Item<'_, 'a>, Error> {
        if self.0.session.state() == State::Quarantined {
            return Err(Error::Quarantined);
        }
        if self.0.item_open {
            return Err(Error::Busy);
        }
        let slot = self.0.next_slot().ok_or(Error::Bounds)?;
        let shape = self
            .0
            .plan
            .slots
            .get(slot)
            .ok_or(Error::Bounds)?
            .ok_or(Error::Bounds)?;
        if !matches!(
            shape.algorithm(),
            Algorithm::Cshake128 | Algorithm::Cshake256
        ) && (name.bit_len() != 0 || custom.bit_len() != 0)
        {
            return Err(Error::Bounds);
        }
        self.0.item_open = true;
        self.0.session.0.issue(
            Request {
                op: 91,
                slot,
                name_bits: u128::try_from(name.bit_len()).map_err(|_| Error::Bounds)?,
                custom_bits: u128::try_from(custom.bit_len()).map_err(|_| Error::Bounds)?,
                ..Request::default()
            },
            &[],
            None,
        )?;
        self.0.session.0.setup_chunks(92, slot, name)?;
        self.0.session.0.setup_chunks(93, slot, custom)?;
        self.0.session.0.issue(
            Request {
                op: 94,
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
                op: 97,
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
/// Packed retained results. No secret slice, cloning or partial batch export.
#[must_use = "declassify or cancel the retained batch"]
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::sha3_batch::Retained<'static>>();\n```"]
pub struct Retained<'a>(Loan<'a>);
impl Retained<'_> {
    /// Public plan describing packed output widths and canonical final bits.
    #[must_use]
    pub fn plan(&self) -> Plan {
        self.0.plan
    }
    /// Export the packed plan transactionally. Inactive slots occupy no bytes;
    /// bytes beyond Plan::output_bytes are zero. Partial bytes are low-bit-first.
    pub fn declassify(
        mut self,
        destination: &mut [u8; 1024],
        _authority: PublicDeclassification,
    ) -> Result<(), Error> {
        let mut public = [0; 1024];
        self.0.session.0.issue(
            Request {
                op: 98,
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
