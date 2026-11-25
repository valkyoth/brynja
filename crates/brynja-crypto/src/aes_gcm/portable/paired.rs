//! Required, whole-pair execution; never a half-native or retrying route.
use super::{Block, Error, Forward, HashRoute, SecretBlock};
#[cfg(test)]
use crate::aes_gcm::interruptions::Step;
use crate::{aes::execution, ghash};

/// Pre-key selection outcome. Only `Unavailable` permits an application
/// that explicitly allows it to choose a portable constructor instead.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairError {
    /// No reviewed pair for the target, compiled AES ISA, or detected GHASH ISA.
    Unavailable,
    /// Failed self-test or unhealthy authority. Do not retry in software.
    Failed,
}

/// Instruction pair selected before importing a key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum PairBackend {
    /// x86-64 AES-NI and PCLMULQDQ.
    AesNiPclmul,
    /// Little-endian AArch64 AES and PMULL.
    ArmAesPmull,
}

/// Thread-local authority for one complete native pair. AES is a static
/// deployment contract (+aes,+sse2 on x86, +aes,+neon on Arm). The
/// multiplier independently checks its required CPU bundle at
/// startup. The deployment must keep the full ISA usable on every eligible
/// CPU. No affinity change, timing qualification, or automatic fallback.
/// The Arm AES kernel's optional DIT scope does not cover PMULL or the whole
/// operation. The pair neither requires whole-operation DIT nor checks x86 DOITM.
/// A specialized binary is not a runtime probe for an incompatible machine.
/// Multiple keys can borrow this pair; an operational failure retires them
/// all. An ordinary authentication rejection does not retire the pair.
#[must_use]
pub struct AesPair {
    backend: PairBackend,
    aes: execution::Authority,
    #[cfg(any(
        all(
            target_arch = "x86_64",
            any(target_os = "linux", target_os = "windows")
        ),
        all(
            target_arch = "aarch64",
            target_endian = "little",
            any(target_os = "linux", target_os = "macos")
        )
    ))]
    hash: core::cell::RefCell<ghash::PairMultiplier>,
}

impl AesPair {
    /// Admit both primitives and run their startup checks before importing
    /// any application key. Portable constructors never call this method.
    pub fn require() -> Result<Self, PairError> {
        #[cfg(any(
            all(
                target_arch = "x86_64",
                any(target_os = "linux", target_os = "windows")
            ),
            all(
                target_arch = "aarch64",
                target_endian = "little",
                any(target_os = "linux", target_os = "macos")
            )
        ))]
        {
            #[cfg(target_arch = "x86_64")]
            let (kernel, backend) = (execution::Kernel::X86AesNi, PairBackend::AesNiPclmul);
            #[cfg(target_arch = "aarch64")]
            let (kernel, backend) = (execution::Kernel::ArmAes, PairBackend::ArmAesPmull);
            let aes = execution::Authority::new(kernel).map_err(|e| match e {
                brynja_crypto_cpu::aes::Error::MissingTargetFeatures => PairError::Unavailable,
                _ => PairError::Failed,
            })?;
            aes.session().map_err(|_| PairError::Failed)?;
            let hash = ghash::PairMultiplier::probe()
                .map_err(|_| PairError::Failed)?
                .ok_or(PairError::Unavailable)?;
            let pair = Self {
                backend,
                aes,
                hash: core::cell::RefCell::new(hash),
            };
            pair.check().map_err(|_| PairError::Failed)?;
            Ok(pair)
        }
        #[cfg(not(any(
            all(
                target_arch = "x86_64",
                any(target_os = "linux", target_os = "windows")
            ),
            all(
                target_arch = "aarch64",
                target_endian = "little",
                any(target_os = "linux", target_os = "macos")
            )
        )))]
        Err(PairError::Unavailable)
    }

    /// Identifies the two native primitives bound to this authority.
    pub fn backend(&self) -> PairBackend {
        self.backend
    }

    /// Permanently retire the pair and all its borrowed owners.
    pub fn retire(&self) {
        self.aes.quarantine();
    }

    fn check(&self) -> Result<(), Error> {
        self.aes.session().map_err(|_| Error::Invariant)?;
        #[cfg(any(
            all(
                target_arch = "x86_64",
                any(target_os = "linux", target_os = "windows")
            ),
            all(
                target_arch = "aarch64",
                target_endian = "little",
                any(target_os = "linux", target_os = "macos")
            )
        ))]
        if self.hash.try_borrow().is_ok_and(|hash| hash.ready()) {
            return Ok(());
        }
        Err(Error::Hash(ghash::Error::Quarantined))
    }

    fn run<T>(&self, work: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
        struct Guard<'a>(&'a AesPair, bool);
        impl Drop for Guard<'_> {
            fn drop(&mut self) {
                if !self.1 {
                    self.0.retire();
                }
            }
        }
        let mut guard = Guard(self, false);
        self.check()?;
        #[cfg(test)]
        Step::Entry.hit().map_err(Error::Hash)?;
        let result = work();
        if result.is_ok() || matches!(result, Err(Error::Authentication)) {
            #[cfg(test)]
            Step::Complete.hit().map_err(Error::Hash)?;
            self.check()?;
            guard.1 = true;
        }
        result
    }
}

impl HashRoute for AesPair {
    fn start<'a>(
        &'a self,
        h: &'a Block,
        state: &'a mut Block,
        budget: u64,
    ) -> Result<ghash::Ghash<'a>, ghash::Error> {
        #[cfg(any(
            all(
                target_arch = "x86_64",
                any(target_os = "linux", target_os = "windows")
            ),
            all(
                target_arch = "aarch64",
                target_endian = "little",
                any(target_os = "linux", target_os = "macos")
            )
        ))]
        {
            self.aes.session().map_err(|_| ghash::Error::Quarantined)?;
            ghash::Ghash::from_pair(&self.hash, h, state, budget)
        }
        #[cfg(not(any(
            all(
                target_arch = "x86_64",
                any(target_os = "linux", target_os = "windows")
            ),
            all(
                target_arch = "aarch64",
                target_endian = "little",
                any(target_os = "linux", target_os = "macos")
            )
        )))]
        {
            let _ = (h, state, budget);
            Err(ghash::Error::Quarantined)
        }
    }
}

macro_rules! key {
    ($name:ident, $width:literal, $size:literal) => {
        pub(super) struct $name<'a>(execution::$name<'a, 'a>, &'a AesPair);
        impl<'a> $name<'a> {
            pub(super) fn new(
                pair: &'a AesPair,
                key: &[u8; $width],
                storage: &'a mut [u8; $size],
            ) -> Result<Self, Error> {
                // Clear supplied destination even when pair admission rejects
                // before the AES owner takes responsibility for it.
                let _ = brynja_core::clear_owned_region(storage);
                pair.run(|| {
                    let aes = execution::$name::new(&pair.aes, key, storage)
                        .map_err(|_| Error::Invariant)?;
                    #[cfg(test)]
                    Step::Expanded.hit().map_err(Error::Hash)?;
                    Ok(Self(aes, pair))
                })
            }
        }
        impl Forward for $name<'_> {
            fn operation<T>(&self, work: impl FnOnce() -> Result<T, Error>) -> Result<T, Error> {
                self.1.run(work)
            }
            fn hash_route(&self) -> &impl HashRoute {
                self.1
            }
            fn encrypt<'b>(
                &self,
                input: &Block,
                out: &'b mut Block,
            ) -> Result<SecretBlock<'b>, Error> {
                let block = self
                    .0
                    .encrypt_block(input, out)
                    .map_err(|_| Error::Invariant)?;
                #[cfg(test)]
                Step::AesBlock.hit().map_err(Error::Hash)?;
                Ok(block)
            }
        }
    };
}
key!(Aes128ExpandedKey, 16, 176);
key!(Aes192ExpandedKey, 24, 208);
key!(Aes256ExpandedKey, 32, 240);

#[cfg(all(
    test,
    any(
        all(
            all(
                target_arch = "x86_64",
                any(target_os = "linux", target_os = "windows")
            ),
            target_feature = "aes",
            target_feature = "sse2"
        ),
        all(
            all(
                target_arch = "aarch64",
                target_endian = "little",
                any(target_os = "linux", target_os = "macos")
            ),
            target_feature = "aes",
            target_feature = "neon"
        )
    )
))]
mod tests {
    extern crate std;
    use super::super::{Buffers, Stage};
    use super::*;

    #[test]
    fn postcheck_precedes_commit() -> Result<(), PairError> {
        // A concurrent-in-sequence revocation must dominate both valid output
        // and a normal authentication rejection, without injecting a check error.
        for computed in [Ok(()), Err(Error::Authentication)] {
            let pair = AesPair::require()?;
            let (mut out, mut scratch) = ([0x55; 4], [0xff; 4]);
            let result = Buffers::InPlace(&mut out).transact(
                Stage(&mut scratch).0,
                Error::Length,
                |_, work| {
                    pair.run(|| {
                        work.fill(0x33);
                        pair.retire();
                        computed
                    })
                },
            );
            assert!(matches!(result, Err(Error::Invariant)));
            assert_eq!((out, scratch), ([0x55; 4], [0; 4]));
            assert!(pair.run(|| Ok(())).is_err());
        }
        Ok(())
    }

    #[test]
    fn unwind_retires_pair() -> Result<(), PairError> {
        let pair = AesPair::require()?;
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            pair.run::<()>(|| std::panic::resume_unwind(std::boxed::Box::new(())))
        }));
        assert!(result.is_err());
        assert!(pair.run(|| Ok(())).is_err());
        Ok(())
    }

    #[test]
    fn frames_use_the_admitted_multiplier() -> Result<(), PairError> {
        let pair = AesPair::require()?;
        let mut a = [0; 16];
        let frame = pair
            .start(&[0; 16], &mut a, 16)
            .map_err(|_| PairError::Failed)?;
        assert!(pair.hash.try_borrow_mut().is_err());
        assert!(matches!(
            pair.start(&[0; 16], &mut [0; 16], 16),
            Err(ghash::Error::Quarantined)
        ));
        drop(frame);
        assert!(pair.check().is_ok());
        pair.retire();
        let mut untouched = [0xa5; 16];
        assert!(matches!(
            pair.start(&[0; 16], &mut untouched, 16),
            Err(ghash::Error::Quarantined)
        ));
        assert_eq!(untouched, [0xa5; 16]);
        Ok(())
    }
}
