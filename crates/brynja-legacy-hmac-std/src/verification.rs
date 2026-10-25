/// Failed authentication, distinct from an operational failure.
///
/// Hosted `verify` returns `Ok(())` only when the supplied tag matches. Checking
/// `is_ok()` or propagating with `?` therefore cannot accept a mismatched tag.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VerificationError<E> {
    /// All selected tag bytes were compared and the candidate did not match.
    Mismatch,
    /// Verification could not complete; this never authorizes a weaker fallback.
    Operation(E),
}

impl<E: core::fmt::Display> core::fmt::Display for VerificationError<E> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Mismatch => f.write_str("legacy HMAC authentication failed"),
            Self::Operation(error) => error.fmt(f),
        }
    }
}
impl<E: std::error::Error + 'static> std::error::Error for VerificationError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Mismatch => None,
            Self::Operation(error) => Some(error),
        }
    }
}

#[cfg(any(feature = "strict-execution", feature = "macos-resident"))]
pub(crate) fn finish<E>(decision: Option<bool>, invariant: E) -> Result<(), VerificationError<E>> {
    match decision {
        Some(true) => Ok(()),
        Some(false) => Err(VerificationError::Mismatch),
        None => Err(VerificationError::Operation(invariant)),
    }
}

#[cfg(all(test, any(feature = "strict-execution", feature = "macos-resident")))]
#[test]
fn success_and_question_mark_cannot_accept_mismatch() {
    fn authorize(decision: Option<bool>) -> Result<bool, VerificationError<u8>> {
        finish(decision, 8)?;
        Ok(true)
    }
    assert_eq!(authorize(Some(true)), Ok(true));
    assert_eq!(authorize(Some(false)), Err(VerificationError::Mismatch));
    assert_eq!(authorize(None), Err(VerificationError::Operation(8)));
    assert!(!finish(Some(false), 8).is_ok());
}
