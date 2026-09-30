//! Public-vector execution experiment only, not a secret-processing interface.
//! Entry requires SHA/SSE2/AVX/AVX2 and enabled XMM/YMM for this whole image.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use brynja_crypto_cpu::{hardened_execution as hard, static_execution as raw};
mod cpu_vectors;
use cpu_vectors::*;

#[cfg(not(test))]
unsafe extern "C" {
    fn PublicProbeAbort() -> !;
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: fixed diagnostic adapter terminates; no cleanup claim on abort.
    unsafe { PublicProbeAbort() }
}

fn sha256() -> Option<usize> {
    let owner = raw::Authority::new(raw::Kernel::X86Sha256).ok()?;
    let mut session = hard::Session::from_static(&owner).ok()?;
    let mut count = 0_usize;
    for (block, expected) in SHA256_BLOCKS.iter().zip(SHA256_EXPECTED) {
        let mut state = [0; 64];
        state[..32].copy_from_slice(&SHA256_IV);
        let mut wide_block = [0; 128];
        wide_block[..64].copy_from_slice(block);
        session.compress(false, &mut state, &wide_block).ok()?;
        if state[..32] != expected || state[32..] != [0; 32] {
            return None;
        }
        count = count.checked_add(1)?;
    }
    owner.quarantine();
    if session.compress(false, &mut [0; 64], &[0; 128]).is_ok() {
        return None;
    }
    Some(count)
}

fn keccak() -> Option<usize> {
    let owner = raw::Authority::new(raw::Kernel::X86Keccak).ok()?;
    let mut session = hard::KeccakSession::from_static(&owner).ok()?;
    let mut count = 0_usize;
    for (input, expected) in KECCAK_INPUT.iter().zip(KECCAK_EXPECTED) {
        let mut state = *input;
        session.permute(&mut state).ok()?;
        if state != expected {
            return None;
        }
        count = count.checked_add(1)?;
    }
    owner.quarantine();
    if session.permute(&mut [0; 200]).is_ok() {
        return None;
    }
    Some(count)
}

macro_rules! batch {
    ($name:ident, $module:ident, $lanes:expr, $iv:ident, $blocks:ident, $expected:ident) => {
        fn $name() -> Option<usize> {
            use brynja_crypto_cpu::$module as batch;
            let owner = batch::Authority::for_compiled_target(batch::Kernel::Avx2).ok()?;
            let session = owner.session().ok()?;
            let mut workspace = batch::Workspace::new();
            let mut count = 0_usize;
            for start in 0..$blocks.len() {
                let mut states = [$iv; $lanes];
                let mut blocks = [$blocks[0]; $lanes];
                let mut expected = [$expected[0]; $lanes];
                for lane in 0..$lanes {
                    let index = start.checked_add(lane)?.checked_rem($blocks.len())?;
                    blocks[lane] = $blocks[index];
                    expected[lane] = $expected[index];
                }
                session
                    .compress_bytes(&mut states, &blocks, &mut workspace)
                    .ok()?;
                if states != expected {
                    return None;
                }
                count = count.checked_add($lanes)?;
            }
            if session.completed_vector_calls() != u64::try_from($blocks.len()).ok()? {
                return None;
            }
            owner.quarantine();
            if session
                .compress_bytes(&mut [$iv; $lanes], &[$blocks[0]; $lanes], &mut workspace)
                .is_ok()
            {
                return None;
            }
            Some(count)
        }
    };
}
batch!(
    batch256,
    sha256_hardened_batch,
    8,
    SHA256_IV,
    SHA256_BLOCKS,
    SHA256_EXPECTED
);
batch!(
    batch512,
    sha512_hardened_batch,
    4,
    SHA512_IV,
    SHA512_BLOCKS,
    SHA512_EXPECTED
);

fn batch_keccak() -> Option<usize> {
    use brynja_crypto_cpu::keccak_hardened_batch as batch;
    let owner = batch::Authority::for_compiled_target(batch::Kernel::Avx2).ok()?;
    let session = owner.session().ok()?;
    let mut workspace = batch::Workspace::new();
    let mut count = 0_usize;
    for start in 0..KECCAK_INPUT.len() {
        let mut states = [[0; 200]; 4];
        let mut expected = [[0; 200]; 4];
        for lane in 0..4 {
            let index = start.checked_add(lane)?.checked_rem(KECCAK_INPUT.len())?;
            states[lane] = KECCAK_INPUT[index];
            expected[lane] = KECCAK_EXPECTED[index];
        }
        session.permute_bytes(&mut states, &mut workspace).ok()?;
        if states != expected {
            return None;
        }
        count = count.checked_add(4)?;
    }
    if session.completed_vector_calls() != u64::try_from(KECCAK_INPUT.len()).ok()? {
        return None;
    }
    owner.quarantine();
    if session
        .permute_bytes(&mut [[0; 200]; 4], &mut workspace)
        .is_ok()
    {
        return None;
    }
    Some(count)
}

#[unsafe(no_mangle)]
pub extern "C" fn PublicCpuKernels(route: usize) -> usize {
    match route {
        1 => sha256(),
        2 => keccak(),
        3 => batch256(),
        4 => batch512(),
        5 => batch_keccak(),
        _ => None,
    }
    .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    macro_rules! campaign {
        ($name:ident, $route:expr, $count:expr) => {
            #[test]
            fn $name() {
                assert_eq!(super::PublicCpuKernels($route), $count);
            }
        };
    }
    campaign!(sha256_native_and_quarantine, 1, 32);
    campaign!(keccak_native_and_quarantine, 2, 16);
    campaign!(sha256_batch_native_and_quarantine, 3, 256);
    campaign!(sha512_batch_native_and_quarantine, 4, 128);
    campaign!(keccak_batch_native_and_quarantine, 5, 64);

    #[test]
    fn invalid_routes_reject() {
        assert_eq!(super::PublicCpuKernels(0), 0);
        assert_eq!(super::PublicCpuKernels(6), 0);
        assert_eq!(super::PublicCpuKernels(usize::MAX), 0);
    }
}
