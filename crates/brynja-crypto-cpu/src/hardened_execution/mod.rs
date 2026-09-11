//! Opt-in secret-bearing SHA-2 compression and Keccak permutation scratch.
//!
//! This is a raw block API, not a complete hash. State and block are borrowed
//! caller-owned secret buffers; the caller must clear them. Private schedule and
//! vector staging clear after every operation, on unwind and on Drop. No claim
//! covers register values, compiler-created copies/spills, caches or aborts.
//! Prefer complete hardened hash APIs in `brynja-hash-sha2` and
//! `brynja-hash-sha3`. The new Keccak route is under v0.24.37 qualification.

mod keccak;
pub(crate) mod keccak_scratch;
pub(crate) mod scratch;
use crate::static_execution::{self as raw, Error, Kernel, Report};
pub use keccak::KeccakSession;
use scratch::Scratch;

enum Route<'a> {
    Static(raw::Session<'a>),
    #[cfg(feature = "runtime-execution")]
    Runtime(crate::runtime_execution::Session<'a>),
}

impl Route<'_> {
    fn check(&self) -> Result<Kernel, Error> {
        match self {
            Self::Static(session) => session.check_hardened(),
            #[cfg(feature = "runtime-execution")]
            Self::Runtime(session) => session.check_hardened(),
        }
    }
    fn quarantine(&self) {
        match self {
            Self::Static(session) => session.quarantine_hardened(),
            #[cfg(feature = "runtime-execution")]
            Self::Runtime(session) => session.quarantine_hardened(),
        }
    }
    fn report(&self) -> Report {
        match self {
            Self::Static(session) => session.report(),
            #[cfg(feature = "runtime-execution")]
            Self::Runtime(session) => session.report(),
        }
    }
}

/// Affine, thread-bound, borrowed authority plus private erasing scratch.
/// Construction runs the actual hardened kernel's KAT before accepting secrets.
/// No fallback, state import, reset, cloning or formatting is available.
///
/// ```compile_fail
/// fn send<T: Send>() {}
/// send::<brynja_crypto_cpu::hardened_execution::Session<'static>>();
/// ```
/// ```compile_fail
/// fn cloneable<T: Clone>() {}
/// cloneable::<brynja_crypto_cpu::hardened_execution::Session<'static>>();
/// ```
pub struct Session<'a> {
    route: Route<'a>,
    scratch: Scratch,
}

impl<'a> Session<'a> {
    /// Borrows a target-specialized authority with a complete CPU feature bundle.
    pub fn from_static(owner: &'a raw::Authority) -> Result<Self, Error> {
        Self::new(Route::Static(owner.session()?))
    }
    /// Borrows the separately established platform-wide runtime guarantee.
    #[cfg(feature = "runtime-execution")]
    pub fn from_runtime(session: crate::runtime_execution::Session<'a>) -> Result<Self, Error> {
        Self::new(Route::Runtime(session))
    }
    fn new(route: Route<'a>) -> Result<Self, Error> {
        let kernel = route.check()?;
        if !matches!(
            kernel,
            Kernel::X86Sha256 | Kernel::ArmSha256 | Kernel::ArmSha512
        ) {
            return Err(Error::WrongOperation);
        }
        let mut session = Self {
            route,
            scratch: Scratch::new(),
        };
        if !session.known_answer(kernel)? {
            session.route.quarantine();
            return Err(Error::Quarantined);
        }
        Ok(session)
    }
    /// Public diagnostic only; cannot renew authority or undo quarantine.
    pub fn report(&self) -> Report {
        self.route.report()
    }
    /// Rechecks health, generation and exact narrow/wide kernel identity.
    pub fn check(&self, wide: bool) -> Result<(), Error> {
        let kernel = self.route.check()?;
        if matches!(
            (wide, kernel),
            (false, Kernel::X86Sha256 | Kernel::ArmSha256) | (true, Kernel::ArmSha512)
        ) {
            Ok(())
        } else {
            Err(Error::WrongOperation)
        }
    }
    /// Compresses a borrowed secret block and big-endian chaining state.
    /// Narrow mode uses the first 32 state bytes and 64 block bytes; wide mode
    /// uses all bytes. Errors before entry preserve state. Caller buffers remain
    /// caller-owned; only this session's private temporaries are erased here.
    pub fn compress(
        &mut self,
        wide: bool,
        state: &mut [u8; 64],
        block: &[u8; 128],
    ) -> Result<(), Error> {
        self.check(wide)?;
        let kernel = self.route.check()?;
        let mut guard = Operation {
            scratch: &mut self.scratch,
            route: &self.route,
            completed: false,
        };
        dispatch(kernel, state, block, guard.scratch)?;
        guard.completed = true;
        Ok(())
    }
    #[inline(never)]
    fn known_answer(&mut self, kernel: Kernel) -> Result<bool, Error> {
        // These local arrays contain public KAT data, never caller secrets.
        let wide = kernel == Kernel::ArmSha512;
        let mut state = [0_u8; 64];
        let mut block = [0_u8; 128];
        let mut expected = [0_u8; 64];
        if wide {
            for (slot, word) in state
                .chunks_exact_mut(8)
                .zip(crate::sha512::initial_state())
            {
                slot.copy_from_slice(&word.to_be_bytes());
            }
            for (slot, word) in expected
                .chunks_exact_mut(8)
                .zip(crate::sha512::abc_digest_state())
            {
                slot.copy_from_slice(&word.to_be_bytes());
            }
            block.copy_from_slice(&crate::sha512::abc_block());
        } else {
            for (slot, word) in state
                .chunks_exact_mut(4)
                .zip(crate::sha256::initial_state())
            {
                slot.copy_from_slice(&word.to_be_bytes());
            }
            for (slot, word) in expected
                .chunks_exact_mut(4)
                .zip(crate::sha256::abc_digest_state())
            {
                slot.copy_from_slice(&word.to_be_bytes());
            }
            block[..64].copy_from_slice(&crate::sha256::abc_block());
        }
        self.compress(wide, core::hint::black_box(&mut state), &block)?;
        Ok(state == expected)
    }
}

struct Operation<'a, 'owner> {
    scratch: &'a mut Scratch,
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

fn dispatch(
    kernel: Kernel,
    state: &mut [u8; 64],
    block: &[u8; 128],
    scratch: &mut Scratch,
) -> Result<(), Error> {
    // Private callers check exact operation, architecture and full authority
    // before this infallible instruction entry. No ordinary kernel is used.
    #[cfg(target_arch = "x86_64")]
    if kernel == Kernel::X86Sha256 {
        crate::x86_sha::compress_secret(state, block, scratch);
        return Ok(());
    }
    #[cfg(target_arch = "aarch64")]
    match kernel {
        Kernel::ArmSha256 => {
            crate::aarch64_sha2::compress_secret(state, block, scratch);
            return Ok(());
        }
        Kernel::ArmSha512 => {
            crate::aarch64_sha2::compress512_secret(state, block, scratch);
            return Ok(());
        }
        _ => {}
    }
    let _ = (kernel, state, block, scratch);
    Err(Error::WrongOperation)
}

#[cfg(test)]
mod tests;
