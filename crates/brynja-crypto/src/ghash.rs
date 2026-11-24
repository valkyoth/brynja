//! Incremental GHASH (NIST SP 800-38D §6.4) over an already-framed sequence
//! of 16-byte blocks. Updates may split blocks at any byte. There is **no**
//! implicit padding, length encoding, tag mask, or authentication decision.
//! Never publish the raw result as a tag: it can reveal the hash subkey.
//! All 128-bit field elements are accepted: a zero subkey produces zero for
//! every input. Do not substitute a zero buffer for failed key derivation.
//!
//! The caller supplies a byte budget, a borrowed subkey in NIST wire order,
//! and distinct workspace and output storage. No allocation or AES backend
//! is needed. Drop clears the borrowed workspace/output, not the caller's key,
//! copies, scalar/vector registers or stack spills; abort and forgotten owners bypass Drop.
//! Development interface: no machine-code timing qualification is claimed.
//! `Ghash::new` stays portable in ordinary Cargo builds. The default-off
//! `ghash-runtime-execution` feature adds explicit hosted backend selection.
//!
//! ```
//! # #[cfg(feature = "hazmat-ghash")]
//! use brynja_crypto::ghash::{Error, Ghash};
//! # #[cfg(feature = "hazmat-ghash")]
//! # fn example() -> Result<(), Error> {
//! // Example subkey and pre-framed block, not a GCM implementation.
//! let h = [0x37; 16];
//! let (mut workspace, mut output) = ([0; 16], [0; 16]);
//! let mut hash = Ghash::new(&h, &mut workspace, 16);
//! hash.update(&[0x11; 5])?;
//! hash.update(&[0x22; 11])?;
//! let intermediate = hash.finish(&mut output)?;
//! // Use intermediate.expose() only inside the higher-level construction.
//! intermediate.clear();
//! assert_eq!(output, [0; 16]);
//! # Ok(()) }
//! # #[cfg(feature = "hazmat-ghash")]
//! # example().unwrap();
//! ```
//!
//! The output cannot alias the live workspace:
//! ```compile_fail,E0499
//! use brynja_crypto::ghash::Ghash;
//! let mut workspace = [0; 16];
//! let hash = Ghash::new(&[0; 16], &mut workspace, 0);
//! let intermediate = hash.finish(&mut workspace);
//! ```

#![forbid(unsafe_code)]

// A stray RUSTFLAGS/config flag alone must not turn ordinary construction
// into a forced-candidate experiment. No build script or production feature.
#[cfg(any(
    brynja_ghash_pclmul_evidence,
    brynja_ghash_pmull_evidence,
    brynja_ghash_rv64_evidence
))]
const _: () = assert!(
    matches!(option_env!("BRYNJA_GHASH_EVIDENCE"), Some(s) if matches!(s.as_bytes(), b"1")),
    "forced GHASH evidence requires BRYNJA_GHASH_EVIDENCE=1"
);

#[cfg(any(
    feature = "ghash-runtime-execution",
    not(any(
        brynja_ghash_pclmul_evidence,
        brynja_ghash_pmull_evidence,
        brynja_ghash_rv64_evidence
    ))
))]
mod field;
#[cfg(feature = "ghash-runtime-execution")]
mod runtime;
#[cfg(feature = "ghash-runtime-execution")]
pub use runtime::{Backend, Mode};

#[cfg(all(
    feature = "ghash-runtime-execution",
    any(
        brynja_ghash_pclmul_evidence,
        brynja_ghash_pmull_evidence,
        brynja_ghash_rv64_evidence
    )
))]
compile_error!("test forced GHASH candidates separately from the public runtime route");
#[cfg(all(
    brynja_ghash_pclmul_evidence,
    not(all(target_arch = "x86_64", feature = "cpu"))
))]
compile_error!("forced GHASH PCLMUL evidence requires x86_64 and the cpu dependency");

#[cfg(all(
    brynja_ghash_pmull_evidence,
    not(all(target_arch = "aarch64", target_endian = "little", feature = "cpu"))
))]
compile_error!("forced GHASH PMULL evidence requires little-endian AArch64 and the cpu dependency");

#[cfg(all(brynja_ghash_pclmul_evidence, target_arch = "x86_64", feature = "cpu"))]
use brynja_crypto_cpu::RequiredPclmul as RequiredProduct;
#[cfg(all(
    brynja_ghash_pmull_evidence,
    target_arch = "aarch64",
    target_endian = "little",
    feature = "cpu"
))]
use brynja_crypto_cpu::RequiredPmull as RequiredProduct;

#[cfg(all(
    brynja_ghash_rv64_evidence,
    not(all(target_arch = "riscv64", target_os = "linux", feature = "cpu"))
))]
compile_error!("forced GHASH RV64 evidence requires RV64 Linux and the cpu dependency");
#[cfg(all(
    brynja_ghash_rv64_evidence,
    target_arch = "riscv64",
    target_os = "linux",
    feature = "cpu"
))]
use brynja_crypto_cpu::RequiredRv64 as RequiredProduct;

use brynja_core::{
    OwnedSecretRegion, SecretMemoryError, SecretRegionInitialization, clear_owned_region,
};
use core::marker::PhantomData;

/// A public length or storage error; contains no secret bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// Required acceleration is not available for this target or CPU.
    #[cfg(feature = "ghash-runtime-execution")]
    Unavailable,
    /// The native backend failed its self-test or is no longer healthy.
    #[cfg(feature = "ghash-runtime-execution")]
    Quarantined,
    /// Forced evidence backend is unavailable or no longer healthy.
    #[cfg(any(
        brynja_ghash_pclmul_evidence,
        brynja_ghash_pmull_evidence,
        brynja_ghash_rv64_evidence
    ))]
    CandidateNotReady,
    /// The entire update would exceed the caller's remaining byte budget.
    LimitExceeded,
    /// The input did not end on a block boundary.
    PartialBlock,
    /// The output region could not be fully initialized.
    Storage(SecretMemoryError),
}

/// One local incremental computation; neither cloneable nor resettable.
#[must_use]
pub struct Ghash<'a> {
    #[cfg(feature = "ghash-runtime-execution")]
    engine: runtime::Engine,
    #[cfg(feature = "ghash-runtime-execution")]
    terminal: bool,
    #[cfg(any(
        brynja_ghash_pclmul_evidence,
        brynja_ghash_pmull_evidence,
        brynja_ghash_rv64_evidence
    ))]
    native: Option<RequiredProduct>,
    h: &'a [u8; 16],
    state: &'a mut [u8; 16],
    used: usize,
    remaining: u64,
    local: PhantomData<*mut ()>,
}

// Observe the primitive itself in unit tests, not a flag in the GCM caller.
// Per-thread storage keeps independent tests from contributing calls.
#[cfg(test)]
extern crate std;
#[cfg(test)]
std::thread_local! {
    pub(crate) static TEST_STARTS: core::cell::Cell<usize> = const { core::cell::Cell::new(0) };
}

impl<'a> Ghash<'a> {
    /// Starts from zero, clearing the workspace. The budget counts all bytes
    /// supplied, including any framing supplied by a higher-level protocol.
    pub fn new(h: &'a [u8; 16], workspace: &'a mut [u8; 16], max_bytes: u64) -> Self {
        #[cfg(test)]
        TEST_STARTS.set(TEST_STARTS.get().wrapping_add(1));
        let _ = clear_owned_region(workspace);
        Self {
            #[cfg(feature = "ghash-runtime-execution")]
            engine: runtime::Engine::Portable,
            #[cfg(feature = "ghash-runtime-execution")]
            terminal: false,
            #[cfg(any(
                brynja_ghash_pclmul_evidence,
                brynja_ghash_pmull_evidence,
                brynja_ghash_rv64_evidence
            ))]
            native: RequiredProduct::detect(),
            h,
            state: workspace,
            used: 0,
            remaining: max_bytes,
            local: PhantomData,
        }
    }

    /// Number of native block products, excluding the KAT. Evidence builds only.
    #[cfg(any(
        brynja_ghash_pclmul_evidence,
        brynja_ghash_pmull_evidence,
        brynja_ghash_rv64_evidence
    ))]
    #[doc(hidden)]
    pub fn native_blocks(&self) -> Result<u64, Error> {
        self.native
            .as_ref()
            .and_then(|n| n.completed())
            .ok_or(Error::CandidateNotReady)
    }

    /// Appends a chunk. An over-budget chunk leaves the entire context unchanged.
    pub fn update(&mut self, bytes: &[u8]) -> Result<(), Error> {
        #[cfg(feature = "ghash-runtime-execution")]
        self.check_health()?;
        #[cfg(any(
            brynja_ghash_pclmul_evidence,
            brynja_ghash_pmull_evidence,
            brynja_ghash_rv64_evidence
        ))]
        self.native_blocks()?;
        let len = u64::try_from(bytes.len()).map_err(|_| Error::LimitExceeded)?;
        let remaining = self
            .remaining
            .checked_sub(len)
            .ok_or(Error::LimitExceeded)?;
        #[cfg(feature = "ghash-runtime-execution")]
        let pending = runtime::Pending::begin(self);
        #[cfg(feature = "ghash-runtime-execution")]
        let owner = &mut *pending.0;
        #[cfg(not(feature = "ghash-runtime-execution"))]
        let owner = self;
        let mut input = bytes.iter();
        while input.len() != 0 {
            // Between complete blocks the state holds the previous product
            // XOR the available prefix of the next block, in place.
            for (dst, src) in owner.state.iter_mut().skip(owner.used).zip(&mut input) {
                *dst ^= src;
                owner.used = owner.used.wrapping_add(1); // at most 16
            }
            if owner.used == 16 {
                #[cfg(not(any(
                    feature = "ghash-runtime-execution",
                    brynja_ghash_pclmul_evidence,
                    brynja_ghash_pmull_evidence,
                    brynja_ghash_rv64_evidence
                )))]
                let value = field::multiply(
                    u128::from_be_bytes(*owner.state),
                    u128::from_be_bytes(*owner.h),
                );
                #[cfg(feature = "ghash-runtime-execution")]
                let value = owner.engine.product(
                    u128::from_be_bytes(*owner.state),
                    u128::from_be_bytes(*owner.h),
                )?;
                #[cfg(any(
                    brynja_ghash_pclmul_evidence,
                    brynja_ghash_pmull_evidence,
                    brynja_ghash_rv64_evidence
                ))]
                let value = owner
                    .native
                    .as_mut()
                    .and_then(|n| {
                        n.product(
                            u128::from_be_bytes(*owner.state),
                            u128::from_be_bytes(*owner.h),
                        )
                    })
                    .ok_or(Error::CandidateNotReady)?;
                *owner.state = value.to_be_bytes();
                owner.used = 0;
            }
        }
        owner.remaining = remaining;
        #[cfg(feature = "ghash-runtime-execution")]
        {
            owner.terminal = false;
        }
        Ok(())
    }

    /// Consumes the context and returns the unmasked, secret GHASH result.
    /// Empty input yields zero. A partial final block leaves output unchanged.
    pub fn finish(self, output: &mut [u8; 16]) -> Result<SecretHash<'_>, Error> {
        #[cfg(feature = "ghash-runtime-execution")]
        self.check_health()?;
        #[cfg(any(
            brynja_ghash_pclmul_evidence,
            brynja_ghash_pmull_evidence,
            brynja_ghash_rv64_evidence
        ))]
        self.native_blocks()?;
        if self.used != 0 {
            return Err(Error::PartialBlock);
        }
        let mut init = SecretRegionInitialization::begin(output).map_err(Error::Storage)?;
        init.write(self.state).map_err(Error::Storage)?;
        Ok(SecretHash {
            region: init.finish().map_err(Error::Storage)?,
            local: PhantomData,
        })
    }
}

impl Drop for Ghash<'_> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.state);
    }
}

/// A secret intermediate for a construction such as GCM; never a public tag.
#[must_use]
pub struct SecretHash<'a> {
    region: OwnedSecretRegion<'a>,
    local: PhantomData<*mut ()>,
}

impl SecretHash<'_> {
    /// Explicitly borrows the unmasked bytes. The caller must protect any copies.
    pub fn expose(&self) -> &[u8] {
        self.region.expose()
    }

    /// Consumes the result and clears the caller's output immediately.
    pub fn clear(self) {
        let _ = self.region.clear();
    }
}
