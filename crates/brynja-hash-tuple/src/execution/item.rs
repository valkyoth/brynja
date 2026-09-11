use super::{Error, Report, core_state::Core};
use crate::Fips202BitString;

/// Exclusive exact-length item writer. Errors and unfinished Drop erase the parent.
#[must_use = "finish the declared item or drop it to cancel its parent"]
pub struct TupleItemWriter<'s, 'a> {
    core: &'s mut Core<'a>,
    complete: bool,
}
impl<'s, 'a> TupleItemWriter<'s, 'a> {
    pub(super) fn new(core: &'s mut Core<'a>) -> Self {
        Self {
            core,
            complete: false,
        }
    }
    /// Remaining item bits; zero does not substitute for a successful finish.
    pub fn remaining_bits(&self) -> u128 {
        self.core.remaining_bits()
    }
    /// Non-authorizing observation of the retained route and health.
    pub fn report(&self) -> Option<Report> {
        self.core.report()
    }
    /// Adds complete bytes. Any rejected fragment closes and clears the parent.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        match super::bits(bytes) {
            Ok(bits) => self.update_bits(bits),
            Err(error) => {
                self.core.cancel();
                Err(error)
            }
        }
    }
    /// Adds canonical arbitrary bits without introducing byte-alignment padding.
    pub fn update_bits(&mut self, bits: Fips202BitString<'_>) -> Result<(), Error> {
        self.core.fragment(bits)
    }
    /// Consumes the writer only after exactly its declared bit count was accepted.
    pub fn finish(mut self) -> Result<(), Error> {
        self.core.complete()?;
        self.complete = true;
        Ok(())
    }
}
impl Drop for TupleItemWriter<'_, '_> {
    fn drop(&mut self) {
        if !self.complete {
            self.core.cancel();
        }
    }
}
