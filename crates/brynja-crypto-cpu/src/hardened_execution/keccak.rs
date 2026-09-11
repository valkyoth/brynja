use super::{Route, keccak_scratch::KeccakScratch};
use crate::static_execution::{self as raw, Error, Kernel, Report};

/// Affine, thread-bound `Keccak-f[1600]` authority with erasing private scratch.
///
/// This raw permutation borrows caller-owned secret state. The caller must erase
/// that state. All seven private aggregate regions are cleared after each call,
/// on recoverable unwind, and on Drop. Registers, compiler copies/spills, abort,
/// caches, and platform storage are not covered. No ordinary kernel handles secrets.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_crypto_cpu::hardened_execution::KeccakSession<'static>>();
/// ```
/// ```compile_fail
/// fn cloneable<T: Clone>() {}
/// cloneable::<brynja_crypto_cpu::hardened_execution::KeccakSession<'static>>();
/// ```
pub struct KeccakSession<'a> {
    route: Route<'a>,
    scratch: KeccakScratch,
}

impl<'a> KeccakSession<'a> {
    /// Requires the complete target-specialized feature bundle and healthy owner.
    pub fn from_static(owner: &'a raw::Authority) -> Result<Self, Error> {
        Self::new(Route::Static(owner.session()?))
    }

    /// Requires an already established platform-wide runtime authority.
    #[cfg(feature = "runtime-execution")]
    pub fn from_runtime(session: crate::runtime_execution::Session<'a>) -> Result<Self, Error> {
        Self::new(Route::Runtime(session))
    }

    fn new(route: Route<'a>) -> Result<Self, Error> {
        let mut session = Self {
            route,
            scratch: KeccakScratch::new(),
        };
        session.check()?;
        // Public KAT input/output. Actual hardened instruction entry is exercised.
        let mut state = [0_u8; 200];
        session.permute(core::hint::black_box(&mut state))?;
        let correct = state
            .as_chunks::<8>()
            .0
            .iter()
            .zip(crate::keccak_constants::ZERO_STATE_RESULT)
            .all(|(bytes, expected)| u64::from_le_bytes(*bytes) == expected);
        if !correct {
            session.route.quarantine();
            return Err(Error::Quarantined);
        }
        Ok(session)
    }

    /// Non-authorizing public route/health observation.
    pub fn report(&self) -> Report {
        self.route.report()
    }

    /// Checks exact identity, health and generation before admitting work.
    pub fn check(&self) -> Result<(), Error> {
        match self.route.check()? {
            Kernel::X86Keccak | Kernel::ArmKeccak => Ok(()),
            _ => Err(Error::WrongOperation),
        }
    }

    /// Permutes 25 little-endian lanes without exposing private scratch.
    /// Errors preserve caller state. An unwind clears scratch and quarantines the
    /// borrowed authority. There is no fallback or state export/import operation.
    pub fn permute(&mut self, state: &mut [u8; 200]) -> Result<(), Error> {
        self.check()?;
        let kernel = self.route.check()?;
        let mut guard = Operation {
            scratch: &mut self.scratch,
            route: &self.route,
            completed: false,
        };
        guard.scratch.lanes.copy_from_slice(state);
        dispatch(kernel, guard.scratch)?;
        state.copy_from_slice(&guard.scratch.lanes);
        guard.completed = true;
        Ok(())
    }
}

struct Operation<'a, 'owner> {
    scratch: &'a mut KeccakScratch,
    route: &'a Route<'owner>,
    completed: bool,
}

impl Drop for Operation<'_, '_> {
    fn drop(&mut self) {
        self.scratch.wipe();
        if !self.completed {
            self.route.quarantine();
        }
    }
}

fn dispatch(kernel: Kernel, scratch: &mut KeccakScratch) -> Result<(), Error> {
    #[cfg(target_arch = "x86_64")]
    if kernel == Kernel::X86Keccak {
        crate::x86_avx2_keccak::permute_secret(scratch);
        return Ok(());
    }
    #[cfg(target_arch = "aarch64")]
    if kernel == Kernel::ArmKeccak {
        crate::aarch64_sha3_keccak::permute_secret(scratch);
        return Ok(());
    }
    let _ = (kernel, scratch);
    Err(Error::WrongOperation)
}

#[cfg(test)]
mod tests;
