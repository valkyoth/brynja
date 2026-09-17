use super::{Error, Kernel};

pub(super) fn sha256(kernel: Kernel, state: &mut [u32; 8], block: &[u8; 64]) -> Result<(), Error> {
    architecture(kernel)?;
    #[cfg(target_arch = "x86_64")]
    if kernel == Kernel::X86Sha256 {
        crate::x86_sha::compress(state, block);
        return Ok(());
    }
    #[cfg(target_arch = "aarch64")]
    if kernel == Kernel::ArmSha256 {
        crate::aarch64_sha2::compress(state, block);
        return Ok(());
    }
    let _ = (state, block);
    Err(Error::WrongOperation)
}

pub(super) fn sha512(
    owner: &super::Authority,
    state: &mut [u64; 8],
    block: &[u8; 128],
) -> Result<(), Error> {
    let kernel = owner.kernel;
    architecture(kernel)?;
    #[cfg(target_arch = "x86_64")]
    if kernel == Kernel::X86Sha512 {
        let permit = crate::x86_sha512::Permit::runtime(owner)?;
        return crate::x86_sha512::compress(&permit, state, block);
    }
    #[cfg(target_arch = "aarch64")]
    if kernel == Kernel::ArmSha512 {
        crate::aarch64_sha2::compress512(state, block);
        return Ok(());
    }
    let _ = (state, block);
    Err(Error::WrongOperation)
}

pub(super) fn keccak(kernel: Kernel, state: &mut [u64; 25]) -> Result<(), Error> {
    architecture(kernel)?;
    #[cfg(target_arch = "x86_64")]
    if kernel == Kernel::X86Keccak {
        crate::x86_avx2_keccak::permute(state);
        return Ok(());
    }
    #[cfg(target_arch = "aarch64")]
    if kernel == Kernel::ArmKeccak {
        crate::aarch64_sha3_keccak::permute(state);
        return Ok(());
    }
    let _ = state;
    Err(Error::WrongOperation)
}

#[inline(never)]
pub(super) fn known_answer(owner: &super::Authority) -> bool {
    let kernel = owner.kernel;
    match kernel {
        Kernel::X86Sha256 | Kernel::ArmSha256 => {
            let mut state = core::hint::black_box(crate::sha256::initial_state());
            sha256(kernel, &mut state, &crate::sha256::abc_block()).is_ok()
                && state == crate::sha256::abc_digest_state()
        }
        Kernel::ArmSha512 | Kernel::X86Sha512 => {
            let mut state = core::hint::black_box(crate::sha512::initial_state());
            sha512(owner, &mut state, &crate::sha512::abc_block()).is_ok()
                && state == crate::sha512::abc_digest_state()
        }
        Kernel::X86Keccak | Kernel::ArmKeccak => {
            let mut state = core::hint::black_box([0; 25]);
            keccak(kernel, &mut state).is_ok()
                && state == crate::keccak_constants::ZERO_STATE_RESULT
        }
    }
}

pub(super) fn architecture(kernel: Kernel) -> Result<(), Error> {
    let supported = match kernel {
        Kernel::X86Sha256 | Kernel::X86Sha512 | Kernel::X86Keccak => cfg!(target_arch = "x86_64"),
        Kernel::ArmSha256 | Kernel::ArmSha512 | Kernel::ArmKeccak => cfg!(target_arch = "aarch64"),
    };
    if supported {
        Ok(())
    } else {
        Err(Error::WrongArchitecture)
    }
}
