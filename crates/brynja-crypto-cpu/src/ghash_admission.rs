//! Candidate-only hosted selection. Portable is a routing decision, not a
//! second implementation or a way to satisfy a required-native test.
use core::{hint::black_box, marker::PhantomData, mem};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Mode {
    #[cfg(test)]
    Prefer,
    Require,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Route {
    #[cfg(test)]
    Portable,
    Accelerated,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum Error {
    Unavailable,
    NotTested,
    Quarantined,
}

// Neither capability reports nor AES feature selections can mint this proof.
// Like other hosted instruction paths this assumes a compatible ISA across
// all CPUs on which the thread is allowed to run.
struct Proof(PhantomData<*mut ()>);

impl Proof {
    fn product(&self, x: u128, h: u128) -> u128 {
        // SAFETY: detect_with_limits constructs Proof only after detecting
        // the complete required host bundle; test masks can only remove features.
        unsafe { super::multiply(x, h) }
    }
}

enum State {
    Unavailable,
    Untested(Proof),
    Ready(Proof),
    Quarantined,
}

pub(super) struct Candidate(State);

impl Candidate {
    pub(super) fn detect() -> Self {
        Self::detect_with_limits([true; super::FEATURE_COUNT])
    }

    fn detect_with_limits(limits: [bool; super::FEATURE_COUNT]) -> Self {
        if super::host_features()
            .into_iter()
            .zip(limits)
            .all(|(found, allowed)| found && allowed)
        {
            Self(State::Untested(Proof(PhantomData)))
        } else {
            Self(State::Unavailable)
        }
    }

    pub(super) fn select(&mut self, mode: Mode) -> Result<Route, Error> {
        self.select_with(mode, Proof::product)
    }

    fn select_with(
        &mut self,
        mode: Mode,
        kat_product: impl FnOnce(&Proof, u128, u128) -> u128,
    ) -> Result<Route, Error> {
        match &self.0 {
            State::Unavailable => {
                return match mode {
                    #[cfg(test)]
                    Mode::Prefer => Ok(Route::Portable),
                    Mode::Require => Err(Error::Unavailable),
                };
            }
            State::Ready(_) => return Ok(Route::Accelerated),
            State::Quarantined => return Err(Error::Quarantined),
            State::Untested(_) => {}
        }
        // Retain terminal state if the kernel unwinds or the answer is wrong.
        let State::Untested(proof) = mem::replace(&mut self.0, State::Quarantined) else {
            return Err(Error::Quarantined);
        };
        // GCM all-zero AES-128 key / one zero plaintext block: H and the
        // ciphertext are public, fixed test inputs. Check the first product,
        // not a value computed by the portable backend at startup.
        let x = black_box(0x0388dace60b6a392f328c2b971b2fe78);
        let h = black_box(0x66e94bd4ef8a2c3b884cfa59ca342b2e);
        if kat_product(&proof, x, h) != 0x5e2ec746917062882c85b0685353deb7 {
            return Err(Error::Quarantined);
        }
        self.0 = State::Ready(proof);
        Ok(Route::Accelerated)
    }

    pub(super) fn product(&mut self, x: u128, h: u128) -> Result<u128, Error> {
        self.product_with(|proof| proof.product(x, h))
    }

    #[cfg(any(
        all(
            feature = "ghash-runtime-execution",
            target_arch = "aarch64",
            target_endian = "little",
            any(target_os = "linux", target_os = "macos")
        ),
        all(
            feature = "ghash-runtime-execution",
            any(
                target_os = "linux",
                all(target_os = "windows", target_arch = "x86_64")
            ),
            any(target_arch = "x86_64", target_arch = "riscv64")
        ),
        brynja_ghash_pclmul_evidence,
        brynja_ghash_pmull_evidence,
        brynja_ghash_rv64_evidence
    ))]
    pub(super) fn ready(&self) -> bool {
        matches!(self.0, State::Ready(_))
    }

    fn product_with(&mut self, run: impl FnOnce(&Proof) -> u128) -> Result<u128, Error> {
        match &self.0 {
            State::Unavailable => return Err(Error::Unavailable),
            State::Untested(_) => return Err(Error::NotTested),
            State::Quarantined => return Err(Error::Quarantined),
            State::Ready(_) => {}
        }
        let State::Ready(proof) = mem::replace(&mut self.0, State::Quarantined) else {
            return Err(Error::Quarantined);
        };
        let out = run(&proof);
        self.0 = State::Ready(proof);
        Ok(out)
    }
}

/// Hosted, forced-native owner for checkout evidence only. No Cargo feature
/// exports this interface. It carries no key or input bytes.
#[cfg(any(
    brynja_ghash_pclmul_evidence,
    brynja_ghash_pmull_evidence,
    brynja_ghash_rv64_evidence
))]
pub struct RequiredProduct {
    candidate: Candidate,
    completed: u64,
}

#[cfg(any(
    brynja_ghash_pclmul_evidence,
    brynja_ghash_pmull_evidence,
    brynja_ghash_rv64_evidence
))]
impl RequiredProduct {
    /// Requires the complete host ISA and a passing direct startup KAT.
    pub fn detect() -> Option<Self> {
        let mut candidate = Candidate::detect();
        candidate.select(Mode::Require).ok()?;
        Some(Self {
            candidate,
            completed: 0,
        })
    }

    /// Computes one field product. Never substitutes portable multiplication.
    pub fn product(&mut self, x: u128, h: u128) -> Option<u128> {
        let next = self.completed.checked_add(1)?;
        let value = self.candidate.product(x, h).ok()?;
        self.completed = next;
        Some(value)
    }

    /// Actual completed products, excluding startup; absent after quarantine.
    pub fn completed(&self) -> Option<u64> {
        self.candidate.ready().then_some(self.completed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};

    #[cfg(all(brynja_cpu_evidence, target_arch = "x86_64"))]
    #[test]
    #[ignore = "requires QEMU with AES but without PCLMULQDQ"]
    fn aes_present_without_pclmul_is_not_ghash_authority() {
        assert!(std::is_x86_feature_detected!("aes"));
        assert!(std::is_x86_feature_detected!("sse2"));
        assert!(!std::is_x86_feature_detected!("pclmulqdq"));
        let mut owner = Candidate::detect();
        assert_eq!(owner.select(Mode::Prefer), Ok(Route::Portable));
        assert_eq!(owner.select(Mode::Require), Err(Error::Unavailable));
        assert_eq!(owner.product(0, 0), Err(Error::Unavailable));
    }

    #[test]
    fn missing_bundle_never_calls_the_kernel() {
        for mask in 0..((1_u8 << super::super::FEATURE_COUNT) - 1) {
            let limits = core::array::from_fn(|i| (mask & (1 << i)) != 0);
            let mut owner = Candidate::detect_with_limits(limits);
            let mut calls = 0;
            for (mode, expected) in [
                (Mode::Prefer, Ok(Route::Portable)),
                (Mode::Require, Err(Error::Unavailable)),
            ] {
                assert_eq!(
                    owner.select_with(mode, |_, _, _| {
                        calls += 1;
                        0
                    }),
                    expected
                );
            }
            assert_eq!(
                owner.product_with(|_| {
                    calls += 1;
                    0
                }),
                Err(Error::Unavailable)
            );
            assert_eq!(calls, 0);
        }
    }

    #[test]
    #[ignore = "requires the candidate instruction bundle"]
    fn wrong_kat_is_terminal_in_both_modes() {
        for mode in [Mode::Require, Mode::Prefer] {
            let mut owner = Candidate::detect();
            assert_eq!(owner.product(0, 0), Err(Error::NotTested));
            assert_eq!(
                owner.select_with(mode, |proof, x, h| proof.product(x, h) ^ 1),
                Err(Error::Quarantined)
            );
            assert_eq!(owner.select(Mode::Prefer), Err(Error::Quarantined));
            assert_eq!(owner.select(Mode::Require), Err(Error::Quarantined));
            assert_eq!(owner.product(0, 0), Err(Error::Quarantined));
        }
    }

    #[test]
    #[ignore = "requires the candidate instruction bundle"]
    fn unwind_latches_and_success_does_not_repeat_kat() {
        for at_startup in [true, false] {
            let mut owner = Candidate::detect();
            if !at_startup {
                assert_eq!(owner.select(Mode::Require), Ok(Route::Accelerated));
                assert_eq!(
                    owner.select_with(Mode::Prefer, |_, _, _| 0),
                    Ok(Route::Accelerated)
                );
            }
            let result = catch_unwind(AssertUnwindSafe(|| {
                if at_startup {
                    let _ = owner.select_with(Mode::Prefer, |_, _, _| {
                        resume_unwind(std::boxed::Box::new(()))
                    });
                } else {
                    let _ = owner.product_with(|_| resume_unwind(std::boxed::Box::new(())));
                }
            }));
            assert!(result.is_err());
            assert_eq!(owner.select(Mode::Prefer), Err(Error::Quarantined));
            assert_eq!(owner.product(0, 0), Err(Error::Quarantined));
        }
    }
}
