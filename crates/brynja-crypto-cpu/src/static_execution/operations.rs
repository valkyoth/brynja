use super::{Error, Kernel};

pub(super) fn sha256(kernel: Kernel, state: &mut [u32; 8], block: &[u8; 64]) -> Result<(), Error> {
    kernel.check_compiled_target()?;
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

pub(super) fn sha512(kernel: Kernel, state: &mut [u64; 8], block: &[u8; 128]) -> Result<(), Error> {
    kernel.check_compiled_target()?;
    #[cfg(target_arch = "aarch64")]
    if kernel == Kernel::ArmSha512 {
        crate::aarch64_sha2::compress512(state, block);
        return Ok(());
    }
    let _ = (state, block);
    Err(Error::WrongOperation)
}

pub(super) fn keccak(kernel: Kernel, state: &mut [u64; 25]) -> Result<(), Error> {
    kernel.check_compiled_target()?;
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
pub(super) fn known_answer(kernel: Kernel) -> bool {
    match kernel {
        Kernel::X86Sha256 | Kernel::ArmSha256 => {
            let mut state = core::hint::black_box(crate::sha256::initial_state());
            sha256(kernel, &mut state, &crate::sha256::abc_block()).is_ok()
                && state == crate::sha256::abc_digest_state()
        }
        Kernel::ArmSha512 => {
            let mut state = core::hint::black_box(crate::sha512::initial_state());
            sha512(kernel, &mut state, &crate::sha512::abc_block()).is_ok()
                && state == crate::sha512::abc_digest_state()
        }
        Kernel::X86Keccak | Kernel::ArmKeccak => {
            let mut state = core::hint::black_box([0; 25]);
            keccak(kernel, &mut state).is_ok()
                && state == crate::keccak_constants::ZERO_STATE_RESULT
        }
    }
}
