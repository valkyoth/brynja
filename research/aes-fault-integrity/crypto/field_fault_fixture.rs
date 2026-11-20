//! Test-only source model of persistent primary-domain constants.
//! This instrumentation is absent from ordinary builds and is not evidence of
//! emitted-immediate corruption or physical fault resistance.
extern crate std;

use std::cell::Cell;

#[derive(Clone, Copy, Eq, PartialEq)]
enum Phase {
    Expansion,
    Transform,
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub(super) enum Site {
    Forward,
    Inverse,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum FaultSite {
    Affine(Site),
    FirstReduction,
}

#[derive(Clone, Copy)]
struct Fault {
    phase: Phase,
    site: FaultSite,
    calls: usize,
    effective: usize,
}

std::thread_local! {
    static ACTIVE_PHASE: Cell<Option<Phase>> = const { Cell::new(None) };
    static ACTIVE_FAULT: Cell<Option<Fault>> = const { Cell::new(None) };
    static REDUCTION_ORDINAL: Cell<usize> = const { Cell::new(0) };
}

pub(in crate::aes) struct PhaseScope;

impl PhaseScope {
    fn enter(phase: Phase) -> Self {
        ACTIVE_PHASE.with(|cell| {
            assert!(cell.get().is_none(), "nested primary-domain fixture");
            cell.set(Some(phase));
        });
        REDUCTION_ORDINAL.with(|cell| cell.set(0));
        Self
    }

    pub(in crate::aes) fn expansion() -> Self {
        Self::enter(Phase::Expansion)
    }

    pub(in crate::aes) fn transform() -> Self {
        Self::enter(Phase::Transform)
    }
}

impl Drop for PhaseScope {
    fn drop(&mut self) {
        ACTIVE_PHASE.with(|cell| cell.set(None));
        REDUCTION_ORDINAL.with(|cell| cell.set(0));
    }
}

pub(in crate::aes) struct PersistentFault;

impl PersistentFault {
    fn install(phase: Phase, site: FaultSite) -> Self {
        ACTIVE_FAULT.with(|cell| {
            assert!(cell.get().is_none(), "nested primary constant fault");
            cell.set(Some(Fault {
                phase,
                site,
                calls: 0,
                effective: 0,
            }));
        });
        Self
    }

    pub(in crate::aes) fn expansion() -> Self {
        Self::install(Phase::Expansion, FaultSite::Affine(Site::Forward))
    }

    pub(in crate::aes) fn transform(inverse: bool) -> Self {
        let site = if inverse {
            Site::Inverse
        } else {
            Site::Forward
        };
        Self::install(Phase::Transform, FaultSite::Affine(site))
    }

    pub(in crate::aes) fn first_reduction() -> Self {
        Self::install(Phase::Transform, FaultSite::FirstReduction)
    }

    pub(in crate::aes) fn take_calls(&self) -> usize {
        self.take_counts().0
    }

    pub(in crate::aes) fn take_counts(&self) -> (usize, usize) {
        ACTIVE_FAULT.with(|cell| {
            let Some(mut fault) = cell.get() else {
                return (0, 0);
            };
            let counts = (fault.calls, fault.effective);
            fault.calls = 0;
            fault.effective = 0;
            cell.set(Some(fault));
            counts
        })
    }
}

impl Drop for PersistentFault {
    fn drop(&mut self) {
        ACTIVE_FAULT.with(|cell| cell.set(None));
    }
}

pub(super) fn affine(site: Site, constant: u8) -> u8 {
    ACTIVE_FAULT.with(|cell| {
        let Some(mut fault) = cell.get() else {
            return constant;
        };
        if ACTIVE_PHASE.with(Cell::get) != Some(fault.phase)
            || FaultSite::Affine(site) != fault.site
        {
            return constant;
        }
        fault.calls = fault.calls.saturating_add(1);
        fault.effective = fault.effective.saturating_add(1);
        cell.set(Some(fault));
        constant ^ 1
    })
}

// The first source-level xtime invocation of each primary transform models a
// single persistent reduction-constant site. A changed constant is ineffective
// when that invocation's input has a clear high bit. This is NOT a mapping to
// one particular instruction in an optimized release artifact.
pub(super) fn reduction(input: u8, constant: u8) -> u8 {
    ACTIVE_FAULT.with(|cell| {
        let Some(mut fault) = cell.get() else {
            return constant;
        };
        if ACTIVE_PHASE.with(Cell::get) != Some(Phase::Transform)
            || fault.site != FaultSite::FirstReduction
        {
            return constant;
        }
        let ordinal = REDUCTION_ORDINAL.with(|cell| {
            let current = cell.get();
            cell.set(current.saturating_add(1));
            current
        });
        if ordinal != 0 {
            return constant;
        }
        fault.calls = fault.calls.saturating_add(1);
        fault.effective = fault.effective.saturating_add(usize::from(input >> 7 != 0));
        cell.set(Some(fault));
        constant ^ 1
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aes::portable::field;

    #[test]
    fn hook_requires_matching_primary_phase_and_site() {
        let ordinary = field::sbox(0);
        let inverse = field::inv_sbox(0);
        let fault = PersistentFault::transform(false);
        assert_eq!(field::sbox(0), ordinary);
        {
            let _expansion = PhaseScope::expansion();
            assert_eq!(field::sbox(0), ordinary);
        }
        {
            let _transform = PhaseScope::transform();
            assert_eq!(field::inv_sbox(0), inverse);
            assert_eq!(field::sbox(0), ordinary ^ 1);
        }
        assert_eq!(fault.take_calls(), 1);
        assert_eq!(field::sbox(0), ordinary);
        assert_eq!(fault.take_calls(), 0);
    }

    #[test]
    fn first_reduction_constant_has_effective_and_ineffective_inputs() {
        let fault = PersistentFault::first_reduction();
        let low = field::xtime(0x7f);
        let high = field::xtime(0x80);
        {
            let _transform = PhaseScope::transform();
            assert_eq!(field::xtime(0x7f), low);
            assert_eq!(field::xtime(0x80), high);
        }
        assert_eq!(fault.take_counts(), (1, 0));
        {
            let _transform = PhaseScope::transform();
            assert_eq!(field::xtime(0x80), high ^ 1);
            assert_eq!(field::xtime(0x7f), low);
        }
        assert_eq!(fault.take_counts(), (1, 1));
    }
}
