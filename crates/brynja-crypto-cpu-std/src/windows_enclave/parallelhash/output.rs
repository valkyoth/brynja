use super::{Algorithm, Bits, Error, Loan, PublicDeclassification, Request, State};
/// Fixed retained output or incremental XOF, never a host secret slice.
#[must_use = "consume or cancel the output"]
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Finalized<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Finalized<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Finalized<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Finalized<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Finalized<'static>>();\n```"]
pub enum Finalized<'a> {
    /// Fixed-length retained result.
    Digest(Retained<'a>),
    /// Incremental enclave-private reader.
    Reader(Reader<'a>),
}
/// Exclusive reader; no clone or reader-position oracle.
#[must_use = "retain output or cancel the reader"]
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Reader<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Reader<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Reader<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Reader<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Reader<'static>>();\n```"]
pub struct Reader<'a>(pub(super) Loan<'a>);
impl<'a> Reader<'a> {
    /// Retain <=1024 bytes; partial final bits require terminal=true.
    pub fn retain(self, width: usize, last: u8, terminal: bool) -> Result<Retained<'a>, Error> {
        self.0.session.0.issue(
            Request {
                op: 105,
                width,
                output_last: last,
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
/// One fixed result or XOF fragment, retained only inside enclave memory.
#[must_use = "declassify, rehash or cancel the result"]
#[doc = "```compile_fail\nfn bound<T: Send>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Sync>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Copy>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: Clone>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Retained<'static>>();\n```"]
#[doc = "```compile_fail\nfn bound<T: core::fmt::Debug>() {}\nbound::<brynja_crypto_cpu_std::windows_enclave::parallelhash::Retained<'static>>();\n```"]
pub struct Retained<'a> {
    pub(super) loan: Loan<'a>,
    pub(super) width: usize,
    pub(super) last: u8,
    pub(super) more: bool,
}
impl<'a> Retained<'a> {
    /// Hash this exact retained bit string as one complete new message, without
    /// host export. Discards any previous reader. For XOF use output=(0,0).
    /// Budget includes retained message bytes and supplied customization bytes.
    pub fn rehash(
        mut self,
        algorithm: Algorithm,
        block: u64,
        custom: Bits<'_>,
        budget: u64,
        output: (usize, u8),
    ) -> Result<Finalized<'a>, Error> {
        if !algorithm.fixed() && output != (0, 0) {
            return Err(Error::Bounds);
        }
        self.loan.session.0.issue(
            Request {
                op: 108,
                algorithm: algorithm.wire(),
                block,
                custom_bits: u128::try_from(custom.bit_len()).map_err(|_| Error::Bounds)?,
                budget,
                width: output.0,
                output_last: output.1,
                ..Request::default()
            },
            &[],
            None,
        )?;
        self.loan.session.0.customization(custom)?;
        self.loan.algorithm = algorithm;
        Ok(super::stream::finished(self.loan, output.0, output.1))
    }
    /// Explicit transactional public export. Failure leaves destination intact.
    /// A nonterminal fragment returns its remaining reader.
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
                op: 106,
                algorithm: self.loan.algorithm.wire(),
                width: self.width,
                output_last: self.last,
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
    /// Destroy the output and any reader without declassification.
    pub fn cancel(self) -> Result<(), Error> {
        self.loan.cancel()
    }
}
