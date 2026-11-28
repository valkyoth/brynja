//! Required-native checkout boundary. No software fallback and no CPU pinning.
use super::{F, limbs, stream};
use std::{hint::black_box, marker::PhantomData};

const KAT: F = [62060317, 5262367, 22716242, 12841259, 60432388];

// Private, thread-local proof of the host AVX2 check. As in hosted GHASH,
// the advertised ISA must remain usable wherever this thread may execute.
struct Proof(PhantomData<*mut ()>);

impl Proof {
    fn groups(&self, h: F, blocks: &[[u8; 64]], r: F) -> F {
        // SAFETY: detect is the only constructor, and checks AVX2 including
        // OS vector-state support before a Proof or a startup KAT exists.
        unsafe { stream::groups(h, blocks, r) }
    }

    fn kat(&self) -> F {
        // Independent integer recurrence modulo 2^130-5: h starts at 7;
        // key bytes 0..15 (already clamped), message bytes 0..127. Exercise
        // two groups, all four distinct lanes, powers and carried state.
        let bytes: [u8; 128] = std::array::from_fn(|i| i as u8);
        self.groups(
            black_box([7, 0, 0, 0, 0]),
            black_box(bytes.as_chunks::<64>().0),
            black_box(limbs(0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100)),
        )
    }
}

enum State {
    Untested(Proof),
    Ready(Proof),
    Quarantined,
}

pub(crate) struct Required(State);

impl Required {
    fn detect(allowed: bool) -> Result<Self, &'static str> {
        if allowed && std::is_x86_feature_detected!("avx2") {
            Ok(Self(State::Untested(Proof(PhantomData))))
        } else {
            Err("unavailable")
        }
    }

    pub(crate) fn probe() -> Result<Self, &'static str> {
        let mut owner = Self::detect(true)?;
        owner.select(Proof::kat)?;
        Ok(owner)
    }

    fn select(&mut self, kat: impl FnOnce(&Proof) -> F) -> Result<(), &'static str> {
        match self.0 {
            State::Ready(_) => return Ok(()),
            State::Quarantined => return Err("quarantined"),
            State::Untested(_) => (),
        }
        let State::Untested(proof) = std::mem::replace(&mut self.0, State::Quarantined) else {
            unreachable!()
        };
        if kat(&proof) != KAT {
            return Err("quarantined");
        }
        self.0 = State::Ready(proof);
        Ok(())
    }

    pub(super) fn ready(&self) -> Result<(), &'static str> {
        match self.0 {
            State::Ready(_) => Ok(()),
            State::Untested(_) => Err("untested"),
            State::Quarantined => Err("quarantined"),
        }
    }

    fn run(&mut self, op: impl FnOnce(&Proof) -> F) -> Result<F, &'static str> {
        self.ready()?;
        let State::Ready(proof) = std::mem::replace(&mut self.0, State::Quarantined) else {
            unreachable!()
        };
        let result = op(&proof);
        self.0 = State::Ready(proof);
        Ok(result)
    }

    pub(super) fn groups(&mut self, h: F, blocks: &[[u8; 64]], r: F) -> Result<F, &'static str> {
        self.run(|proof| proof.groups(h, blocks, r))
    }

    #[cfg(test)]
    pub(super) fn interrupt_for_test(&mut self) {
        let _ = self.run(|_| panic!("interrupted operation"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::panic::{AssertUnwindSafe, catch_unwind};

    #[test]
    fn no_proof_before_detection_and_full_kat() {
        assert!(matches!(Required::detect(false), Err("unavailable")));
        let mut cpu = Required::detect(true).unwrap();
        assert_eq!(cpu.run(|_| panic!("ran before startup")), Err("untested"));
        cpu.select(Proof::kat).unwrap();
        cpu.select(|_| panic!("repeated startup")).unwrap();
        for i in 0..5 {
            let mut bad = Required::detect(true).unwrap();
            assert_eq!(
                bad.select(|p| {
                    let mut got = p.kat();
                    got[i] ^= 1;
                    got
                }),
                Err("quarantined")
            );
            assert_eq!(bad.select(|_| panic!("retried")), Err("quarantined"));
            assert_eq!(bad.run(|_| panic!("executed")), Err("quarantined"));
        }
    }

    #[test]
    fn unwind_never_restores_the_same_authority() {
        for startup in [true, false] {
            let mut cpu = Required::detect(true).unwrap();
            let failed = catch_unwind(AssertUnwindSafe(|| {
                if startup {
                    let _ = cpu.select(|_| panic!("startup interruption"));
                } else {
                    cpu.select(Proof::kat).unwrap();
                    let _ = cpu.run(|_| panic!("operation interruption"));
                }
            }));
            assert!(failed.is_err());
            assert_eq!(cpu.ready(), Err("quarantined"));
            assert_eq!(cpu.select(Proof::kat), Err("quarantined"));
        }
    }
}
