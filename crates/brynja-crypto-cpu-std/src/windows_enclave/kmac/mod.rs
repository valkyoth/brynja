//! Scalar KMAC/KMACXOF using a version-eight enclave worker.
//! Caller-owned key/message buffers remain outside enclave storage. Retained
//! tags/readers never expose host secret slices. Only explicit declassification
//! or a public verification decision leaves the enclave. No hardware route,
//! production-signing qualification or Windows ARM64 support is implied.
//! Requires `strict-sha2` (the enclave owner) and `strict-kmac`. Fatal abort is
//! outside Drop cleanup; abandoned handles quarantine their owning session.
use super::kmac_wire::Request;
use super::{Error, ImagePolicy, PublicDeclassification, State};
use core::marker::PhantomData;
use std::path::Path;
mod output;
mod transport;
pub use brynja_mac_kmac::Fips202BitString as Bits;
pub use output::{Reader, Retained};
use transport::{Channel, Transport};

/// Public SP 800-185 identity. Keys must meet its 128/256-bit strength.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Algorithm {
    /// Fixed-output KMAC128.
    Kmac128,
    /// Fixed-output KMAC256.
    Kmac256,
    /// Extendable-output KMACXOF128.
    KmacXof128,
    /// Extendable-output KMACXOF256.
    KmacXof256,
}
impl Algorithm {
    fn wire(self) -> u64 {
        match self {
            Self::Kmac128 => 1,
            Self::Kmac256 => 2,
            Self::KmacXof128 => 3,
            Self::KmacXof256 => 4,
        }
    }
    fn fixed(self) -> bool {
        matches!(self, Self::Kmac128 | Self::Kmac256)
    }
    fn strength(self) -> u128 {
        if matches!(self, Self::Kmac128 | Self::KmacXof128) {
            128
        } else {
            256
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
    fn begin(
        &mut self,
        algorithm: Algorithm,
        key: Bits<'_>,
        custom: Bits<'_>,
    ) -> Result<(), Error> {
        let key_bits = u128::try_from(key.bit_len()).map_err(|_| Error::Bounds)?;
        if key_bits < algorithm.strength() {
            self.state = State::Quarantined;
            return Err(Error::Bounds);
        }
        self.issue(
            Request {
                op: 40,
                algorithm: algorithm.wire(),
                key_bits,
                custom_bits: u128::try_from(custom.bit_len()).map_err(|_| Error::Bounds)?,
                ..Request::default()
            },
            &[],
            None,
        )?;
        self.chunks(41, custom)?;
        self.simple(42)?;
        self.chunks(43, key)?;
        self.simple(44)
    }
    fn verify(&mut self, algorithm: Algorithm, candidate: Bits<'_>) -> Result<bool, Error> {
        let mut decision = [0xa5];
        self.issue(
            Request {
                op: 49,
                algorithm: algorithm.wire(),
                last: candidate.valid_bits_in_last_byte(),
                ..Request::default()
            },
            candidate.as_bytes(),
            Some(&mut decision),
        )?;
        match decision {
            [0] => {
                self.state = State::Ready;
                Ok(false)
            }
            [1] => {
                self.state = State::Ready;
                Ok(true)
            }
            _ => {
                self.state = State::Quarantined;
                Err(Error::Protocol)
            }
        }
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
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::kmac::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::kmac::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::kmac::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::kmac::Session>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::kmac::Session>();\n```"]
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
    /// Stream exact key/S bits using bounded snapshots, then lend the message
    /// stream. Key and customization total length need not fit one request.
    pub fn stream(
        &mut self,
        algorithm: Algorithm,
        key: Bits<'_>,
        custom: Bits<'_>,
    ) -> Result<Stream<'_>, Error> {
        match self.0.state {
            State::Ready => (),
            State::Busy => return Err(Error::Busy),
            _ => return Err(Error::Quarantined),
        }
        self.0.begin(algorithm, key, custom)?;
        Ok(Stream(Loan {
            session: self,
            algorithm,
            active: true,
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
}
impl Loan<'_> {
    fn cancel(mut self) -> Result<(), Error> {
        self.session.0.simple(51)?;
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
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::kmac::Stream<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::kmac::Stream<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::kmac::Stream<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::kmac::Stream<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::kmac::Stream<'static>>();\n```"]
pub struct Stream<'a>(Loan<'a>);
impl<'a> Stream<'a> {
    /// Copy bounded snapshots of caller-owned bytes into the enclave.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        if input.is_empty() {
            return self.0.session.0.simple(45);
        }
        for chunk in input.chunks(1024) {
            self.0.session.0.issue(
                Request {
                    op: 45,
                    last: 8,
                    ..Request::default()
                },
                chunk,
                None,
            )?;
        }
        Ok(())
    }
    fn finish_tail(&mut self, input: Bits<'_>, output_bits: usize) -> Result<(), Error> {
        let complete = input.bit_len() / 8;
        self.update(input.as_bytes().get(..complete).ok_or(Error::Bounds)?)?;
        let tail = input.as_bytes().get(complete..).ok_or(Error::Bounds)?;
        self.0.session.0.issue(
            Request {
                op: 46,
                width: output_bits,
                last: if tail.is_empty() {
                    0
                } else {
                    input.valid_bits_in_last_byte()
                },
                ..Request::default()
            },
            tail,
            None,
        )
    }
    /// Retain a full-strength fixed tag with exact output shape (at most 1024
    /// bytes). The last byte contains 1..=8 low bits; partial high bits are zero.
    pub fn finalize(self, width: usize, last: u8) -> Result<Retained<'a>, Error> {
        self.finalize_bits(Bits::new(&[], 0).map_err(|_| Error::Bounds)?, width, last)
    }
    /// Finish a fixed tag with an additional arbitrary-bit message tail.
    pub fn finalize_bits(
        mut self,
        input: Bits<'_>,
        width: usize,
        last: u8,
    ) -> Result<Retained<'a>, Error> {
        if !self.0.algorithm.fixed() || width == 0 || width > 1024 || !(1..=8).contains(&last) {
            return Err(Error::Bounds);
        }
        let count = width
            .checked_sub(1)
            .and_then(|n| n.checked_mul(8))
            .and_then(|n| n.checked_add(usize::from(last)))
            .ok_or(Error::Bounds)?;
        if u128::try_from(count).map_err(|_| Error::Bounds)? < self.0.algorithm.strength() {
            return Err(Error::Bounds);
        }
        self.finish_tail(input, count)?;
        Ok(Retained {
            loan: self.0,
            width,
            last,
            more: false,
        })
    }
    /// Finalize KMACXOF without exposing its reader to host memory.
    pub fn finalize_xof(self) -> Result<Reader<'a>, Error> {
        self.finalize_bits_xof(Bits::new(&[], 0).map_err(|_| Error::Bounds)?)
    }
    /// Finalize KMACXOF with an arbitrary-bit final message.
    pub fn finalize_bits_xof(mut self, input: Bits<'_>) -> Result<Reader<'a>, Error> {
        if self.0.algorithm.fixed() {
            return Err(Error::Bounds);
        }
        self.finish_tail(input, 0)?;
        Ok(Reader(self.0))
    }
    /// Clear without exposing bytes and permit session reuse on success.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
}
#[cfg(test)]
mod tests;
