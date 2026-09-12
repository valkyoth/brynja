use super::{Error, Preference};
use brynja_crypto_cpu::static_execution as specialized;
use brynja_crypto_cpu_std::execution as hosted;
use brynja_hash_parallel::execution::{KeccakSession, Mode};
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
use hosted::Kernel;

pub(super) enum Selection {
    Portable,
    Hosted(hosted::Authority),
    Static(specialized::Authority),
}
impl Selection {
    pub(super) fn new(preference: Preference) -> Result<Self, Error> {
        if preference == Preference::Portable {
            return Ok(Self::Portable);
        }
        #[cfg(target_arch = "x86_64")]
        let kernel = Kernel::X86Keccak;
        #[cfg(target_arch = "aarch64")]
        let kernel = Kernel::ArmKeccak;
        #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
        return if preference == Preference::Prefer {
            Ok(Self::Portable)
        } else {
            Err(Error::Unavailable)
        };
        #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
        {
            if preference == Preference::RequireStatic {
                return Ok(Self::Static(
                    specialized::Authority::new(kernel).map_err(Error::Static)?,
                ));
            }
            let mode = if preference == Preference::Require {
                hosted::Mode::Require
            } else {
                hosted::Mode::Prefer
            };
            Ok(Self::Hosted(
                hosted::Authority::new(kernel, mode).map_err(Error::Hosted)?,
            ))
        }
    }
    pub(super) fn mode(&self) -> Result<Mode<'_>, Error> {
        let owner = match self {
            Self::Portable => return Ok(Mode::Portable),
            Self::Static(owner) => {
                return Ok(Mode::Require(Some(
                    KeccakSession::from_static(owner).map_err(Error::Static)?,
                )));
            }
            Self::Hosted(owner) => owner,
        };
        match owner.session().map_err(Error::Hosted)? {
            None => Ok(Mode::Prefer(None)),
            Some(session) => Ok(Mode::Require(Some(
                KeccakSession::from_runtime(session)
                    .map_err(|error| Error::Hosted(hosted::Error::Kernel(error)))?,
            ))),
        }
    }
}
