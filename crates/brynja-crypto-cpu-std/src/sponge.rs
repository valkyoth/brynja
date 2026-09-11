//! Opt-in hosted ordinary SHA-3/SHAKE/cSHAKE constructors.
//!
//! One explicit caller-owned selection; no global installation or affinity changes.
//! All inputs, including cSHAKE N/S, must be classified public. No hardened or
//! keyed construction may use these non-erasing owners. Portable defaults stay unchanged.
//!
//! ```
//! use brynja_crypto_cpu_std::sponge::{Sponge, Mode, Public};
//! let owner = Sponge::new(Mode::Prefer).unwrap();
//! let selection = owner.report(); // inspect portable fallback and its reason
//! let mut hash = owner.sha3_256().unwrap();
//! hash.update(Public::new(b"abc")).unwrap();
//! let digest = hash.finalize().unwrap();
//! ```
//! ```compile_fail,E0505
//! use brynja_crypto_cpu_std::sponge::{Sponge, Mode};
//! let owner = Sponge::new(Mode::Portable).unwrap();
//! let mut reader = owner.shake128().unwrap().finalize_xof().unwrap();
//! drop(owner);
//! reader.squeeze(&mut [0; 1]).unwrap();
//! ```

use crate::execution as host;
pub use api::{Public, PublicBits};
use brynja_hash_sha3::execution as api;
pub use host::{Mode, Report, Route, Unavailable};

/// Distinguishes host admission failures from a selected hash execution failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Error {
    /// No hosted permit or lost owner health. Never authorizes fallback.
    Hosted(host::Error),
    /// Selected sponge initialization or execution failed.
    Execution(api::Error),
}
impl From<host::Error> for Error {
    fn from(error: host::Error) -> Self {
        Self::Hosted(error)
    }
}
impl From<api::Error> for Error {
    fn from(error: api::Error) -> Self {
        Self::Execution(error)
    }
}
impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "hosted sponge failure: {self:?}")
    }
}
impl std::error::Error for Error {}

/// Caller-owned selection borrowed by all returned states and readers.
/// Neither Send nor Sync. That does not itself prevent OS CPU/VM migration.
pub struct Sponge {
    owner: host::Authority,
}

impl Sponge {
    /// Selects a host-appropriate Keccak route once with an explicit preference.
    /// On unsupported platforms Prefer is observably portable and Require rejects.
    pub fn new(mode: Mode) -> Result<Self, Error> {
        let kernel = if cfg!(target_arch = "aarch64") {
            host::Kernel::ArmKeccak
        } else {
            host::Kernel::X86Keccak
        };
        Ok(Self {
            owner: host::Authority::new(kernel, mode)?,
        })
    }
    /// Current selection, fallback reason and health; this report grants no authority.
    #[must_use]
    pub fn report(&self) -> Report {
        self.owner.report()
    }
    /// Quarantines an accelerated owner and all its borrowed states/readers.
    /// An explicitly portable owner has no kernel to quarantine.
    pub fn quarantine(&self) {
        self.owner.quarantine();
    }
    /// Obtains a healthy borrowed execution route for one-shot or custom streaming use.
    /// Only an explicit pre-execution portable selection returns a portable route.
    pub fn execution(&self) -> Result<api::Execution<'_>, Error> {
        execution_from_session(self.owner.session())
    }
    /// Starts ordinary SHA3-224.
    pub fn sha3_224(&self) -> Result<api::Sha3_224<'_>, Error> {
        Ok(api::Sha3_224::new(self.execution()?)?)
    }
    /// Starts ordinary SHA3-256.
    pub fn sha3_256(&self) -> Result<api::Sha3_256<'_>, Error> {
        Ok(api::Sha3_256::new(self.execution()?)?)
    }
    /// Starts ordinary SHA3-384.
    pub fn sha3_384(&self) -> Result<api::Sha3_384<'_>, Error> {
        Ok(api::Sha3_384::new(self.execution()?)?)
    }
    /// Starts ordinary SHA3-512.
    pub fn sha3_512(&self) -> Result<api::Sha3_512<'_>, Error> {
        Ok(api::Sha3_512::new(self.execution()?)?)
    }
    /// Starts ordinary SHAKE128.
    pub fn shake128(&self) -> Result<api::Shake128<'_>, Error> {
        Ok(api::Shake128::new(self.execution()?)?)
    }
    /// Starts ordinary SHAKE256.
    pub fn shake256(&self) -> Result<api::Shake256<'_>, Error> {
        Ok(api::Shake256::new(self.execution()?)?)
    }
    /// Starts ordinary byte-oriented cSHAKE128 with explicit public N/S.
    pub fn cshake128(
        &self,
        name: Public<'_>,
        custom: Public<'_>,
    ) -> Result<api::Cshake128<'_>, Error> {
        Ok(api::Cshake128::new(self.execution()?, name, custom)?)
    }
    /// Starts ordinary byte-oriented cSHAKE256 with explicit public N/S.
    pub fn cshake256(
        &self,
        name: Public<'_>,
        custom: Public<'_>,
    ) -> Result<api::Cshake256<'_>, Error> {
        Ok(api::Cshake256::new(self.execution()?, name, custom)?)
    }
    /// Starts ordinary arbitrary-bit cSHAKE128 with explicit public N/S.
    pub fn cshake128_bits(
        &self,
        name: PublicBits<'_>,
        custom: PublicBits<'_>,
    ) -> Result<api::Cshake128<'_>, Error> {
        Ok(api::Cshake128::new_bits(self.execution()?, name, custom)?)
    }
    /// Starts ordinary arbitrary-bit cSHAKE256 with explicit public N/S.
    pub fn cshake256_bits(
        &self,
        name: PublicBits<'_>,
        custom: PublicBits<'_>,
    ) -> Result<api::Cshake256<'_>, Error> {
        Ok(api::Cshake256::new_bits(self.execution()?, name, custom)?)
    }
}

#[cfg(test)]
mod tests;

fn execution_from_session(
    session: Result<Option<host::Session<'_>>, host::Error>,
) -> Result<api::Execution<'_>, Error> {
    match session? {
        Some(session) => Ok(api::Execution::from_runtime(session)?),
        None => Ok(api::Execution::portable()),
    }
}
