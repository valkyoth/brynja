use crate::static_execution::{Error, Kernel};

/// Private-field instruction permit, borrowed from an established authority.
/// A kernel identity or feature boolean alone cannot construct this value.
pub(crate) struct Permit<'a> {
    source: Source<'a>,
}

enum Source<'a> {
    Compiled(core::marker::PhantomData<&'a ()>),
    #[cfg(feature = "runtime-execution")]
    Runtime(&'a crate::runtime_execution::Authority),
}

impl Permit<'_> {
    pub(crate) fn compiled() -> Result<Self, Error> {
        Kernel::X86Sha512.check_compiled_target()?;
        Ok(Self {
            source: Source::Compiled(core::marker::PhantomData),
        })
    }

    pub(crate) fn check(&self) -> Result<(), Error> {
        match self.source {
            Source::Compiled(_) => Kernel::X86Sha512.check_compiled_target(),
            #[cfg(feature = "runtime-execution")]
            Source::Runtime(owner) => {
                let report = owner.report();
                if report.kernel != Kernel::X86Sha512 {
                    return Err(Error::WrongOperation);
                }
                if report.health == crate::runtime_execution::Health::Quarantined {
                    return Err(Error::Quarantined);
                }
                // Testing is permitted only for startup KATs. Runtime owners
                // can only be constructed by the platform's lifetime guarantee;
                // no caller-controlled booleans or reports can mint one.
                Ok(())
            }
        }
    }
}

#[cfg(feature = "runtime-execution")]
impl<'a> Permit<'a> {
    pub(crate) fn runtime(owner: &'a crate::runtime_execution::Authority) -> Result<Self, Error> {
        let permit = Self {
            source: Source::Runtime(owner),
        };
        permit.check()?;
        Ok(permit)
    }
}
