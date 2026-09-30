use super::{Algorithm, Bits, Error, Loan, PublicDeclassification, Request, State};
/// Finalization distinguishes fixed digests from incremental XOF readers.
#[must_use = "consume or cancel the output"]
pub enum Finalized<'a> {
    /// Fixed digest, retained inside enclave storage.
    Digest(Retained<'a>),
    /// Incremental SHAKE/cSHAKE reader.
    Reader(Reader<'a>),
}
pub(super) fn finished(loan: Loan<'_>) -> Finalized<'_> {
    if let Some(width) = loan.algorithm.width() {
        Finalized::Digest(Retained {
            loan,
            width,
            last: 8,
            more: false,
        })
    } else {
        Finalized::Reader(Reader(loan))
    }
}
/// Affine XOF reader. No position/preflight oracle or host secret output API.
#[must_use = "retain output or cancel the reader"]
pub struct Reader<'a>(pub(super) Loan<'a>);
impl<'a> Reader<'a> {
    /// Retain at most 1024 bytes per fragment. Nonterminal fragments are complete
    /// bytes; a partial low-bit final byte requires terminal=true. Empty output
    /// requires last=0. The total stream is not limited to one fragment.
    pub fn retain(self, width: usize, last: u8, terminal: bool) -> Result<Retained<'a>, Error> {
        self.0.session.0.issue(
            Request {
                op: 27,
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
    /// Clear the reader without producing output.
    pub fn cancel(self) -> Result<(), Error> {
        self.0.cancel()
    }
}
/// One retained digest or XOF fragment. Neither copies nor secret slices escape.
#[must_use = "declassify, rehash or cancel the retained result"]
pub struct Retained<'a> {
    pub(super) loan: Loan<'a>,
    pub(super) width: usize,
    pub(super) last: u8,
    pub(super) more: bool,
}
impl<'a> Retained<'a> {
    /// Rehash this exact bit string with empty N/S. Discard any previous reader.
    pub fn rehash(mut self, algorithm: Algorithm) -> Result<Finalized<'a>, Error> {
        self.loan.session.0.issue(
            Request {
                op: 24,
                algorithm: algorithm.wire(),
                ..Request::default()
            },
            &[],
            None,
        )?;
        self.loan.algorithm = algorithm;
        Ok(finished(self.loan))
    }
    /// Rehash inside the enclave using a streamed cSHAKE domain.
    pub fn rehash_customized(
        mut self,
        algorithm: Algorithm,
        name: Bits<'_>,
        custom: Bits<'_>,
    ) -> Result<Finalized<'a>, Error> {
        self.loan.session.0.custom(algorithm, name, custom)?;
        self.loan.algorithm = algorithm;
        Ok(finished(self.loan))
    }
    /// Explicit public output with exact width and transactional host commit.
    /// A nonterminal fragment returns its reader; terminal output permits reuse.
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
                op: 25,
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
    /// Destroy retained output and any reader without host export.
    pub fn cancel(self) -> Result<(), Error> {
        self.loan.cancel()
    }
}
