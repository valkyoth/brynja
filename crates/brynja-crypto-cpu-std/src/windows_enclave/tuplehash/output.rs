use super::{Algorithm, Bits, Error, Loan, PublicDeclassification, Request, State, Stream};
/// Affine enclave-private TupleHashXOF reader; no host secret-slice API.
#[must_use = "retain output or cancel the reader"]
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Reader<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Reader<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Reader<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Reader<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Reader<'static>>();\n```"]
pub struct Reader<'a>(pub(super) Loan<'a>);
impl<'a> Reader<'a> {
    /// Retain a bounded fragment; only terminal fragments may end in partial
    /// low bits. Empty fragments use last=0. Total output may span many calls.
    pub fn retain(self, width: usize, last: u8, terminal: bool) -> Result<Retained<'a>, Error> {
        self.0.session.0.issue(
            Request {
                op: 67,
                width,
                last,
                terminal,
                ..Request::default()
            },
            &[],
            None,
        )?;
        Ok(Retained {
            loan: self.0,
            width,
            last,
            more: !terminal,
        })
    }
    /// Clear without exporting output.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
}
/// Retained fixed tag or XOF fragment; no Clone, Debug, Send or Sync.
#[must_use = "declassify, rehash or cancel the result"]
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::tuplehash::Retained<'static>>();\n```"]
pub struct Retained<'a> {
    pub(super) loan: Loan<'a>,
    pub(super) width: usize,
    pub(super) last: u8,
    pub(super) more: bool,
}
impl<'a> Retained<'a> {
    /// Hash retained exact bits as the first item of a new tuple; discard any old reader.
    pub fn rehash(mut self, algorithm: Algorithm, custom: Bits<'_>) -> Result<Stream<'a>, Error> {
        self.loan.session.0.issue(
            Request {
                op: 69,
                algorithm: algorithm.wire(),
                custom_bits: u128::try_from(custom.bit_len()).map_err(|_| Error::Bounds)?,
                ..Request::default()
            },
            &[],
            None,
        )?;
        self.loan.session.0.chunks(61, custom)?;
        self.loan.session.0.simple(62)?;
        self.loan.algorithm = algorithm;
        Ok(Stream(self.loan))
    }
    /// Transactional explicit public export. Failure leaves the destination
    /// unchanged. Nonterminal XOF fragments return the remaining reader.
    pub fn declassify(
        mut self,
        destination: &mut [u8],
        _authority: PublicDeclassification,
    ) -> Result<Option<Reader<'a>>, Error> {
        if destination.len() != self.width {
            return Err(Error::Bounds);
        }
        let mut public = [0; 1024];
        let stage = public.get_mut(..self.width).ok_or(Error::Bounds)?;
        self.loan.session.0.issue(
            Request {
                op: 68,
                algorithm: self.loan.algorithm.wire(),
                width: self.width,
                last: self.last,
                ..Request::default()
            },
            &[],
            Some(stage),
        )?;
        destination.copy_from_slice(stage);
        if self.more {
            Ok(Some(Reader(self.loan)))
        } else {
            self.loan.session.0.state = State::Ready;
            self.loan.active = false;
            Ok(None)
        }
    }
    /// Clear retained output and any reader without exporting it.
    pub fn cancel(self) -> Result<(), Error> {
        self.loan.cancel()
    }
}
