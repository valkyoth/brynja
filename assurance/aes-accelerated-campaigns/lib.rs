//! Test-only, package-external adapter: no portable owner or fallback exists here.
#![forbid(unsafe_code)]

#[cfg(feature = "facade")]
use brynja::crypto::aes as public;
#[cfg(feature = "direct")]
use brynja_crypto::aes as public;

pub mod aes {
    pub use super::public::execution::{
        Aes128ExpandedKey, Aes128Key, Aes192ExpandedKey, Aes192Key, Aes256ExpandedKey, Aes256Key,
        Authority, Error,
    };
    pub use super::public::{PublicCiphertext, SecretBlock};
}

use public::execution::{Authority, Health, Kernel};
type Check<T> = Result<T, Box<dyn std::error::Error>>;

pub struct ForcedAuthority {
    #[cfg(not(feature = "hosted"))]
    owner: Authority,
    #[cfg(feature = "hosted")]
    owner: brynja_crypto_cpu_std::aes::Authority,
}

impl ForcedAuthority {
    pub fn get(&self) -> Check<&Authority> {
        #[cfg(not(feature = "hosted"))]
        let authority = &self.owner;
        #[cfg(feature = "hosted")]
        let authority = self
            .owner
            .kernel_authority()
            .map_err(|e| format!("{e:?}"))?
            .ok_or("portable route is forbidden")?;
        if authority.report().health != Health::Healthy {
            return Err("accelerated authority is not healthy".into());
        }
        Ok(authority)
    }
}

pub fn forced_authority() -> Check<ForcedAuthority> {
    #[cfg(target_arch = "x86_64")]
    let kernel = Kernel::X86AesNi;
    #[cfg(target_arch = "aarch64")]
    let kernel = Kernel::ArmAes;
    #[cfg(target_arch = "riscv64")]
    let kernel = Kernel::RiscVScalarAes;
    #[cfg(not(feature = "hosted"))]
    let owner = Authority::new(kernel).map_err(|e| format!("{e:?}"))?;
    #[cfg(feature = "hosted")]
    let owner = brynja_crypto_cpu_std::aes::Authority::new(
        kernel,
        brynja_crypto_cpu_std::aes::Mode::Require,
    )
    .map_err(|e| format!("{e:?}"))?;
    let result = ForcedAuthority { owner };
    result.get()?;
    println!("AES_FORCED_AUTHORITY: {kernel:?}");
    Ok(result)
}
