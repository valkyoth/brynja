use super::{Bits, Error, Finalized, Loan, Reader, Request, Retained};
/// Exclusive message loan. Drop quarantines; forget leaves the session busy.
#[must_use = "finalize or cancel the stream"]
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Stream<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Stream<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Stream<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Stream<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Stream<'static>>();\n```"]
pub struct Stream<'a>(pub(super) Loan<'a>);
impl<'a> Stream<'a> {
    /// Absorb bytes through bounded snapshots; caller copies remain unprotected.
    pub fn update(&mut self, input: &[u8]) -> Result<(), Error> {
        if input.is_empty() {
            return self.0.session.0.simple(103);
        }
        for chunk in input.chunks(1024) {
            self.0.session.0.issue(
                Request {
                    op: 103,
                    last: 8,
                    ..Request::default()
                },
                chunk,
                None,
            )?;
        }
        Ok(())
    }
    fn finish(mut self, tail: Bits<'_>, width: usize, last: u8) -> Result<Loan<'a>, Error> {
        let complete = tail.bit_len() / 8;
        self.update(tail.as_bytes().get(..complete).ok_or(Error::Bounds)?)?;
        let input = tail.as_bytes().get(complete..).ok_or(Error::Bounds)?;
        self.0.session.0.issue(
            Request {
                op: 104,
                width,
                output_last: last,
                last: if input.is_empty() {
                    0
                } else {
                    tail.valid_bits_in_last_byte()
                },
                ..Request::default()
            },
            input,
            None,
        )?;
        Ok(self.0)
    }
    /// Fixed output <=1024 bytes, exact low-bit final shape (empty uses 0/0).
    pub fn finalize(self, tail: Bits<'_>, width: usize, last: u8) -> Result<Retained<'a>, Error> {
        if !self.0.algorithm.fixed() {
            return Err(Error::Bounds);
        }
        Ok(Retained {
            loan: self.finish(tail, width, last)?,
            width,
            last,
            more: false,
        })
    }
    /// Enter the XOF domain; no total output bound, only per-fragment bounds.
    pub fn finalize_xof(self, tail: Bits<'_>) -> Result<Reader<'a>, Error> {
        if self.0.algorithm.fixed() {
            return Err(Error::Bounds);
        }
        Ok(Reader(self.finish(tail, 0, 0)?))
    }
    /// Clear without export; reuse requires confirmed cancellation.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
}
pub(super) fn finished(loan: Loan<'_>, width: usize, last: u8) -> Finalized<'_> {
    if loan.algorithm.fixed() {
        Finalized::Digest(Retained {
            loan,
            width,
            last,
            more: false,
        })
    } else {
        Finalized::Reader(Reader(loan))
    }
}
