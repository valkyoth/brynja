//! Scalar TupleHash/TupleHashXOF using a version-nine enclave worker.
//! Caller inputs remain outside enclave protection. Only explicit public
//! declassification exports output. Requires strict-sha2 and strict-tuplehash.
//! Native qualification, production signing and hardware routes remain pending.
//! Abandoned handles quarantine; fatal abort is outside Drop cleanup.
//!
//! ```no_run
//! use brynja_crypto_cpu_std::windows_enclave::{tuplehash::{Session, Algorithm, Bits}, Error, PublicDeclassification};
//! # fn example(session: &mut Session) -> Result<(), Error> {
//! let custom = Bits::new(&[], 0).map_err(|_| Error::Bounds)?;
//! let mut tuple = session.stream(Algorithm::TupleHash128, custom)?;
//! let mut item = tuple.item(24)?;
//! item.update(Bits::new(b"abc", 8).map_err(|_| Error::Bounds)?)?;
//! item.finish()?;
//! let retained = tuple.finalize(32, 8)?;
//! let mut public = [0; 32];
//! let _ = retained.declassify(&mut public, PublicDeclassification::acknowledge())?;
//! # Ok(()) }
//! ```
use super::tuple_wire::Request;
use super::{Error, ImagePolicy, PublicDeclassification, State};
use core::marker::PhantomData;
use std::path::Path;
mod output;
mod transport;
pub use brynja_hash_tuple::Fips202BitString as Bits;
pub use output::{Reader, Retained};
use transport::{Channel, Transport};

/// Public SP 800-185 TupleHash identity.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// Fixed-output TupleHash128.
    TupleHash128,
    /// Fixed-output TupleHash256.
    TupleHash256,
    /// Extendable-output TupleHashXOF128.
    TupleHashXof128,
    /// Extendable-output TupleHashXOF256.
    TupleHashXof256,
}
impl Algorithm {
    fn wire(self) -> u64 {
        match self {
            Self::TupleHash128 => 1,
            Self::TupleHash256 => 2,
            Self::TupleHashXof128 => 3,
            Self::TupleHashXof256 => 4,
        }
    }
    fn fixed(self) -> bool {
        matches!(self, Self::TupleHash128 | Self::TupleHash256)
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
    fn chunks(&mut self, op: usize, input: Bits<'_>) -> Result<(), Error> {
        if input.bit_len() == 0 {
            // Empty customization is already complete in cSHAKE's setup state.
            // Item updates still enter the worker to enforce its item-phase latch.
            return if op == 64 { self.simple(op) } else { Ok(()) };
        }
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
        if !input.bit_len().is_multiple_of(8) {
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
    fn begin(&mut self, algorithm: Algorithm, custom: Bits<'_>) -> Result<(), Error> {
        self.issue(
            Request {
                op: 60,
                algorithm: algorithm.wire(),
                custom_bits: u128::try_from(custom.bit_len()).map_err(|_| Error::Bounds)?,
                ..Request::default()
            },
            &[],
            None,
        )?;
        self.chunks(61, custom)?;
        self.simple(62)
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

/// Thread-bound enclave session. No application callbacks or raw handles.
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Session>();\n```"]
pub struct Session(Owner<Transport>);
impl Session {
    /// Requires production image trust; no development-signing fallback exists.
    pub fn open(location: &Path, policy: &'static ImagePolicy) -> Result<Self, Error> {
        Ok(Self(Owner {
            transport: Transport::open(location, policy)?,
            state: State::Ready,
            sequence: 0,
            thread_bound: PhantomData,
        }))
    }
    /// Public lifecycle, not secret length, reader position or byte exposure.
    pub fn state(&self) -> State {
        self.0.state
    }
    /// Stream customization, then lend an exclusive tuple builder.
    pub fn stream(&mut self, algorithm: Algorithm, custom: Bits<'_>) -> Result<Stream<'_>, Error> {
        match self.0.state {
            State::Ready => (),
            State::Busy => return Err(Error::Busy),
            _ => return Err(Error::Quarantined),
        }
        self.0.begin(algorithm, custom)?;
        Ok(Stream(Loan {
            session: self,
            algorithm,
            active: true,
            item_open: false,
        }))
    }
    /// Clear even forgotten loans; release only after confirmed destruction.
    pub fn close(&mut self) -> Result<(), Error> {
        self.0.close()
    }
}
struct Loan<'a> {
    session: &'a mut Session,
    algorithm: Algorithm,
    active: bool,
    item_open: bool,
}
impl Loan<'_> {
    fn cancel(mut self) -> Result<(), Error> {
        self.session.0.simple(70)?;
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
/// Exclusive message stream; drop quarantines and forget leaves the parent busy.
#[must_use = "finalize or cancel the stream"]
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Stream<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Stream<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Stream<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Stream<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Stream<'static>>();\n```"]
pub struct Stream<'a>(Loan<'a>);
impl<'a> Stream<'a> {
    /// Begin one tuple item with an exact public bit count. Empty items count.
    /// Abandoning an item quarantines the session; forgetting it cannot finish it.
    pub fn item(&mut self, bits: u128) -> Result<Item<'_, 'a>, Error> {
        if self.0.item_open {
            return Err(Error::Busy);
        }
        self.0.item_open = true;
        self.0.session.0.issue(
            Request {
                op: 63,
                item_bits: bits,
                ..Request::default()
            },
            &[],
            None,
        )?;
        Ok(Item {
            stream: self,
            complete: false,
        })
    }
    /// Retain fixed output, including an empty output. Partial bytes use low bits.
    pub fn finalize(self, width: usize, last: u8) -> Result<Retained<'a>, Error> {
        if self.0.session.0.state == State::Quarantined {
            return Err(Error::Quarantined);
        }
        if self.0.item_open || !self.0.algorithm.fixed() {
            return Err(Error::Bounds);
        }
        self.0.session.0.issue(
            Request {
                op: 66,
                width,
                last,
                ..Request::default()
            },
            &[],
            None,
        )?;
        Ok(Retained {
            loan: self.0,
            width,
            last,
            more: false,
        })
    }
    /// Finalize a TupleHashXOF tuple and retain the reader inside the enclave.
    pub fn finalize_xof(self) -> Result<Reader<'a>, Error> {
        if self.0.session.0.state == State::Quarantined {
            return Err(Error::Quarantined);
        }
        if self.0.item_open || self.0.algorithm.fixed() {
            return Err(Error::Bounds);
        }
        self.0.session.0.simple(66)?;
        Ok(Reader(self.0))
    }
    /// Clear without exposing bytes.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
}
/// Exclusive exact-length item writer. No secret state or output is host-readable.
#[must_use = "finish the item or abandon the session"]
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Item<'static, 'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Item<'static, 'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Item<'static, 'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Item<'static, 'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Item<'static, 'static>>();\n```"]
pub struct Item<'s, 'a> {
    stream: &'s mut Stream<'a>,
    complete: bool,
}
impl Item<'_, '_> {
    /// Append canonical low-bit input using bounded enclave snapshots.
    pub fn update(&mut self, input: Bits<'_>) -> Result<(), Error> {
        self.stream.0.session.0.chunks(64, input)
    }
    /// Finish only after the declared item length has been supplied.
    pub fn finish(mut self) -> Result<(), Error> {
        self.stream.0.session.0.simple(65)?;
        self.stream.0.item_open = false;
        self.complete = true;
        Ok(())
    }
}
impl Drop for Item<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.stream.0.session.0.state = State::Quarantined;
        }
    }
}
#[cfg(test)]
mod tests;
