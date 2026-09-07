/// Value-free batch failure. No error contains message data or partial digests.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Md5BatchError {
    /// The supplied compression budget was exhausted before further work.
    WorkLimit,
    /// The caller requested cancellation before the next bounded step.
    Cancelled,
    /// A canonical message or accumulated work length was not representable.
    MessageTooLong,
    /// The explicit backend is unhealthy, unavailable or not authorized.
    Backend,
    /// Typed secret destination initialization failed.
    SecretMemory,
}

#[cfg(kani)]
mod proofs {
    use super::*;
    #[kani::proof]
    fn md5_batch_budget_is_checked_before_mutation() {
        let budget: usize = kani::any();
        let request: usize = kani::any();
        let mut control = Md5BatchControl::new(budget);
        let result = control.charge(request);
        match budget.checked_sub(request) {
            Some(expected) => {
                assert_eq!(result, Ok(()));
                assert_eq!(control.remaining(), expected);
            }
            None => {
                assert_eq!(result, Err(Md5BatchError::WorkLimit));
                assert_eq!(control.remaining(), budget);
            }
        }
    }
    #[kani::proof]
    fn md5_batch_cancellation_never_consumes_budget() {
        let budget: usize = kani::any();
        let request: usize = kani::any();
        let mut callback = || true;
        let mut control = Md5BatchControl::with_cancellation(budget, &mut callback);
        assert_eq!(control.charge(request), Err(Md5BatchError::Cancelled));
        assert_eq!(control.remaining(), budget);
    }
}
impl core::fmt::Display for Md5BatchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match self {
            Self::WorkLimit => "MD5 batch work limit",
            Self::Cancelled => "MD5 batch cancelled",
            Self::MessageTooLong => "MD5 batch message or work length",
            Self::Backend => "MD5 batch backend unavailable",
            Self::SecretMemory => "MD5 batch secret destination",
        })
    }
}
impl core::error::Error for Md5BatchError {}

/// Caller-owned public compression budget and optional cancellation observer.
///
/// The budget charges actual independent-message compression blocks, including
/// padding and every active SIMD lane. Cancellation is checked before each step
/// and before output commit. A callback may request cancellation, never admission.
/// Callbacks should not panic; if they unwind, batch and secret outputs clear.
/// An abort cannot execute cleanup. Consumed work is never refunded on failure.
pub struct Md5BatchControl<'control> {
    remaining: usize,
    cancelled: Option<&'control mut dyn FnMut() -> bool>,
}
impl<'control> Md5BatchControl<'control> {
    /// Creates a bounded synchronous operation without a cancellation observer.
    pub const fn new(max_compressions: usize) -> Self {
        Self {
            remaining: max_compressions,
            cancelled: None,
        }
    }
    /// Creates a bounded operation; returning true requests cancellation.
    pub fn with_cancellation(
        max_compressions: usize,
        cancelled: &'control mut dyn FnMut() -> bool,
    ) -> Self {
        Self {
            remaining: max_compressions,
            cancelled: Some(cancelled),
        }
    }
    /// Remaining public work allowance, shared if reused by later operations.
    pub const fn remaining(&self) -> usize {
        self.remaining
    }
    pub(super) fn charge(&mut self, blocks: usize) -> Result<(), Md5BatchError> {
        if let Some(cancelled) = &mut self.cancelled
            && cancelled()
        {
            return Err(Md5BatchError::Cancelled);
        }
        self.remaining = self
            .remaining
            .checked_sub(blocks)
            .ok_or(Md5BatchError::WorkLimit)?;
        Ok(())
    }
}
