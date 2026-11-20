//! Primary-domain storage for private functional/evidence tests only.
use super::{Error, Scratch};
use crate::aes::portable;

pub(super) enum Primary {
    A128(Scratch<176>),
    A192(Scratch<208>),
    A256(Scratch<240>),
}

impl Primary {
    pub(super) fn new(width: usize) -> Result<Self, Error> {
        match width {
            16 => Ok(Self::A128(Scratch::new())),
            24 => Ok(Self::A192(Scratch::new())),
            32 => Ok(Self::A256(Scratch::new())),
            _ => Err(Error::SecretMemory),
        }
    }

    pub(super) fn width(&self) -> usize {
        match self {
            Self::A128(_) => 16,
            Self::A192(_) => 24,
            Self::A256(_) => 32,
        }
    }

    pub(super) fn as_bytes(&self) -> &[u8] {
        match self {
            Self::A128(s) => &s.0,
            Self::A192(s) => &s.0,
            Self::A256(s) => &s.0,
        }
    }

    #[cfg(all(test, brynja_fault_evidence))]
    pub(super) fn bytes(&mut self) -> &mut [u8] {
        match self {
            Self::A128(s) => &mut s.0,
            Self::A192(s) => &mut s.0,
            Self::A256(s) => &mut s.0,
        }
    }

    pub(super) fn expand(&mut self, key: &[u8]) -> Result<(), Error> {
        #[cfg(all(test, brynja_fault_evidence))]
        let _phase = portable::field_fault_fixture::PhaseScope::expansion();
        match self {
            Self::A128(s) => portable::expand(key, &mut s.0),
            Self::A192(s) => portable::wide::expand::<24, 208, 12>(key, &mut s.0),
            Self::A256(s) => portable::wide::expand::<32, 240, 14>(key, &mut s.0),
        }
    }

    pub(super) fn transform(&self, state: &mut [u8; 16], inverse: bool) -> Result<(), Error> {
        #[cfg(all(test, brynja_fault_evidence))]
        let _phase = portable::field_fault_fixture::PhaseScope::transform();
        match self {
            Self::A128(s) => portable::transform(state, &s.0, inverse),
            Self::A192(s) => portable::wide::transform::<24, 208, 12>(state, &s.0, inverse),
            Self::A256(s) => portable::wide::transform::<32, 240, 14>(state, &s.0, inverse),
        }
    }
}
