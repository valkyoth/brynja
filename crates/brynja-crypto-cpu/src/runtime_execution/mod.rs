//! Default-off platform-authorized ordinary kernel execution.
//!
//! Prefer the safe hosted adapter in `brynja-crypto-cpu-std`. This low-level
//! boundary cannot discover CPU features or establish scheduler guarantees.
//! No hardened secret processing, allocation, probing or global registration.

#![allow(unsafe_code)]

pub use crate::static_execution::{Error, Health, Kernel, Report};
use core::{cell::Cell, marker::PhantomData};

mod operations;

/// Platform-authorized, thread-bound kernel owner. Not a hash state.
///
/// Reports and feature booleans cannot create this owner in safe Rust.
/// Quarantine is permanent for this owner, not a global FIPS error latch.
///
/// ```compile_fail
/// use brynja_crypto_cpu::runtime_execution::{Authority, Kernel};
/// let owner = Authority::from_platform(Kernel::ArmSha256);
/// ```
/// ```compile_fail
/// use brynja_crypto_cpu::runtime_execution::Authority;
/// fn send<T: Send>() {}
/// send::<Authority>();
/// ```
pub struct Authority {
    kernel: Kernel,
    health: Cell<Health>,
    generation: Cell<u64>,
    thread_bound: PhantomData<*mut ()>,
}

impl Authority {
    /// Establishes an owner and runs the actual selected kernel's startup KAT.
    /// A failed KAT returns a quarantined owner, never a portable replacement.
    ///
    /// # Safety
    /// The caller must guarantee the kernel's complete CPU feature bundle and
    /// required OS register state on EVERY CPU on which this thread can execute
    /// for the owner's entire lifetime, including scheduling, hotplug and VM
    /// migration. X86Sha256 requires SHA and SSE2; X86Keccak requires AVX/AVX2
    /// and OS-enabled XMM/YMM state; ArmSha256 requires NEON/SHA2;
    /// ArmSha512 and ArmKeccak require NEON and Rust's full SHA3/SHA512 bundle.
    /// A current-core CPUID result, a successful KAT, thread-bound ownership
    /// or affinity observation alone does not discharge this obligation.
    pub unsafe fn from_platform(kernel: Kernel) -> Result<Self, Error> {
        operations::architecture(kernel)?;
        let owner = Self {
            kernel,
            health: Cell::new(Health::Testing),
            generation: Cell::new(1),
            thread_bound: PhantomData,
        };
        owner.complete_startup(operations::known_answer(kernel));
        Ok(owner)
    }

    fn complete_startup(&self, passed: bool) {
        self.generation.set(2);
        self.health.set(if passed {
            Health::Healthy
        } else {
            Health::Quarantined
        });
    }

    /// Non-authorizing observation; no host identifiers or secret data.
    pub fn report(&self) -> Report {
        Report {
            kernel: self.kernel,
            health: self.health.get(),
            generation: self.generation.get(),
        }
    }

    /// Obtains a borrowed session only after successful startup testing.
    pub fn session(&self) -> Result<Session<'_>, Error> {
        self.check(self.generation.get())?;
        Ok(Session {
            owner: self,
            generation: self.generation.get(),
        })
    }

    /// Invalidates all borrowed sessions. No reset, wrapping counter or retry.
    pub fn quarantine(&self) {
        if self.health.get() != Health::Quarantined {
            self.health.set(Health::Quarantined);
            self.generation.set(3);
        }
    }

    fn check(&self, generation: u64) -> Result<(), Error> {
        match self.health.get() {
            Health::Testing => return Err(Error::NotReady),
            Health::Quarantined => return Err(Error::Quarantined),
            Health::Healthy => {}
        }
        if self.generation.get() != generation {
            return Err(Error::StaleGeneration);
        }
        operations::architecture(self.kernel)
    }
}

/// Borrowed ordinary public-data session. Every error preserves input state.
///
/// No owned-state clearing is provided. Do not supply confidential inputs.
///
/// ```compile_fail
/// use brynja_crypto_cpu::runtime_execution::{Authority, Session};
/// fn escape(owner: Authority) -> Session<'static> { owner.session().unwrap() }
/// ```
pub struct Session<'a> {
    owner: &'a Authority,
    generation: u64,
}

impl Session<'_> {
    /// Current owner health; this observation cannot authorize execution.
    pub fn report(&self) -> Report {
        self.owner.report()
    }

    /// Compresses one SHA-256 block after checking owner health and identity.
    pub fn compress_sha256(&self, state: &mut [u32; 8], block: &[u8; 64]) -> Result<(), Error> {
        self.owner.check(self.generation)?;
        operations::sha256(self.owner.kernel, state, block)
    }

    /// Compresses one SHA-512-family block; padding belongs to the consumer.
    pub fn compress_sha512(&self, state: &mut [u64; 8], block: &[u8; 128]) -> Result<(), Error> {
        self.owner.check(self.generation)?;
        operations::sha512(self.owner.kernel, state, block)
    }

    /// Executes `Keccak-f[1600]`, not an entire SHA-3/SHAKE construction.
    pub fn permute_keccak(&self, state: &mut [u64; 25]) -> Result<(), Error> {
        self.owner.check(self.generation)?;
        operations::keccak(self.owner.kernel, state)
    }
}

#[cfg(test)]
mod tests;
