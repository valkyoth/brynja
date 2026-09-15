use super::Error;
/// Finite cumulative permutation budget and caller cancellation. Work and callbacks
/// expose public batch shape; this does not hide message lengths.
pub struct Control<'a> {
    remaining: u64,
    used: u64,
    cancelled: &'a mut dyn FnMut() -> bool,
}

impl<'a> Control<'a> {
    /// Creates a budget; scalar permutations cost one, SIMD calls cost their width.
    pub fn new(maximum_permutations: u64, cancelled: &'a mut dyn FnMut() -> bool) -> Self {
        Self {
            remaining: maximum_permutations,
            used: 0,
            cancelled,
        }
    }
    /// Cumulative charged work, including padding and work before cancellation.
    pub const fn used(&self) -> u64 {
        self.used
    }
    /// Remaining budget, never implicitly replenished.
    pub const fn remaining(&self) -> u64 {
        self.remaining
    }
    pub(super) fn poll(&mut self) -> Result<(), Error> {
        if (self.cancelled)() {
            Err(Error::Cancelled)
        } else {
            Ok(())
        }
    }
    pub(super) fn charge(&mut self, amount: u64) -> Result<(), Error> {
        self.poll()?;
        let remaining = self.remaining.checked_sub(amount).ok_or(Error::WorkLimit)?;
        let used = self.used.checked_add(amount).ok_or(Error::Invariant)?;
        self.remaining = remaining;
        self.used = used;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn accounting_boundaries_are_atomic() -> Result<(), Error> {
        let mut cancel = || false;
        let mut c = Control::new(u64::MAX, &mut cancel);
        c.charge(u64::MAX)?;
        assert_eq!(c.used(), u64::MAX);
        assert_eq!(c.remaining(), 0);
        c.charge(0)?;
        assert_eq!(c.charge(1), Err(Error::WorkLimit));
        c.remaining = 1; // inject inconsistent internal accounting
        assert_eq!(c.charge(1), Err(Error::Invariant));
        assert_eq!(c.used(), u64::MAX);
        assert_eq!(c.remaining(), 1);
        Ok(())
    }
}
