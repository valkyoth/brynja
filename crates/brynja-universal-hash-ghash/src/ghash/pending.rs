use super::{Error, Ghash};

// Begin only after budget admission; leave terminal on error or unwind.
pub(super) struct Pending<'b, 'a>(pub(super) &'b mut Ghash<'a>);

impl<'b, 'a> Pending<'b, 'a> {
    pub(super) fn begin(owner: &'b mut Ghash<'a>) -> Self {
        owner.terminal = true;
        Self(owner)
    }
}

impl Drop for Pending<'_, '_> {
    fn drop(&mut self) {
        if self.0.terminal {
            let _ = super::clear_owned_region(self.0.state);
            self.0.used = 0;
            self.0.remaining = 0;
        }
    }
}

impl<'a> Ghash<'a> {
    pub(super) fn check_health(&self) -> Result<(), Error> {
        if self.terminal {
            return Err(Error::Quarantined);
        }
        #[cfg(feature = "ghash-runtime-execution")]
        self.engine.check()?;
        Ok(())
    }
}
