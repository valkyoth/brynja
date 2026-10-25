use crate::Error;

/// Authentication failure, distinct from an incomplete operation.
///
/// `verify` returns `Ok` only for matching tags. MD5 batch mismatch carries the
/// completed, public work report so hosted adapters can validate its provenance
/// on mismatches as well as matches. It never carries a tag or lane decisions.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError<R = ()> {
    /// Comparison completed and at least one selected tag byte differed.
    Mismatch(R),
    /// Verification could not complete; never authorizes fallback.
    Operation(Error),
}

impl<R> From<Error> for VerificationError<R> {
    fn from(error: Error) -> Self {
        Self::Operation(error)
    }
}

impl<R> VerificationError<R> {
    /// Discards only public work metadata, preserving the failure category.
    pub fn without_report(self) -> VerificationError {
        match self {
            Self::Mismatch(_) => VerificationError::Mismatch(()),
            Self::Operation(error) => VerificationError::Operation(error),
        }
    }
}
