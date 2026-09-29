//! Public-vector enclave experiment using unchanged Brynja portable SHA-256.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

mod sha256_vectors;
use sha256_vectors::{EXPECTED, LENGTHS};

#[repr(C)]
#[derive(Debug)]
pub struct Report {
    pub status: usize,
    pub address: usize,
    pub comparisons: usize,
    pub cleared: usize,
}

#[cfg(not(test))]
unsafe extern "C" {
    fn PublicProbeAbort() -> !;
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: linked exclusively to the experiment's non-returning __fastfail
    // adapter. No secret arguments, fallback, unwinding or cleanup claim.
    unsafe { PublicProbeAbort() }
}

fn fill(case: usize, input: &mut [u8; 1024]) -> Option<usize> {
    const TEXT: [&[u8]; 4] = [b"", b"abc",
        b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
        b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"];
    let length = *LENGTHS.get(case)?;
    for (index, byte) in input.iter_mut().enumerate() {
        *byte = ((index % 256) as u8)
            .wrapping_mul(17)
            .wrapping_add(case as u8);
    }
    if let Some(text) = TEXT.get(case) {
        input.get_mut(..length)?.copy_from_slice(text);
    }
    Some(length)
}

fn compare(actual: &[u8; 32], expected: &[u8; 32], output: &mut [u8; 32]) -> bool {
    output.copy_from_slice(actual);
    if cfg!(probe_bad_sha256_digest) {
        if let Some(first) = output.first_mut() {
            *first ^= 1;
        }
    }
    output == expected
}

fn campaign(input: &mut [u8; 1024], output: &mut [u8; 32], limit: usize) -> Option<usize> {
    let mut comparisons = 0_usize;
    for (case, expected) in EXPECTED.iter().enumerate().take(limit) {
        let length = fill(case, input)?;
        let message = input.get(..length)?;
        let digest = brynja_hash_sha2::sha256(message).ok()?;
        if !compare(digest.as_bytes(), expected, output) {
            return None;
        }
        comparisons = comparisons.checked_add(1)?;
        let mut state = brynja_hash_sha2::Sha256::new();
        state.update(&[]).ok()?;
        for chunk in message.chunks(7) {
            state.update(chunk).ok()?;
        }
        let digest = state.finalize();
        if !compare(digest.as_bytes(), expected, output) {
            return None;
        }
        comparisons = comparisons.checked_add(1)?;
    }
    Some(comparisons)
}

#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn PublicRustWork(mode: usize, low: usize, high: usize) -> Report {
    let mut report = Report {
        status: 0,
        address: 0,
        comparisons: 0,
        cleared: 0,
    };
    if mode > 3 {
        return report;
    }
    let mut input = [0_u8; 1024];
    let mut output = [0_u8; 32];
    let address = input.as_ptr() as usize;
    let out_address = output.as_ptr() as usize;
    if high < low
        || high - low != 65536
        || address < low
        || address > high - 1024
        || out_address < low
        || out_address > high - 32
    {
        return report;
    }
    report.address = address;
    let count = campaign(
        &mut input,
        &mut output,
        match mode {
            1 => 10,
            2 => 0,
            _ => 20,
        },
    );
    // Explicit local buffers only. Ordinary hash state, temporaries and compiler
    // spills are not claimed to be locally erased; outer full-window clearing
    // is a separate observation. All inputs and outputs are PUBLIC.
    for byte in input.iter_mut().chain(output.iter_mut()) {
        if !cfg!(probe_skip_sha256_clear) {
            // SAFETY: exclusive reference to an initialized local-array byte.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
    }
    let mut residue = 0_u8;
    for byte in input.iter().chain(output.iter()) {
        // SAFETY: shared reference to an initialized local-array byte.
        residue |= unsafe { core::ptr::read_volatile(byte) };
    }
    report.cleared = usize::from(residue == 0);
    if let Some(count) = count {
        report.comparisons = count;
        if residue == 0 {
            report.status = mode + 1;
        }
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_vectors_match_both_existing_apis() {
        assert_eq!(campaign(&mut [0; 1024], &mut [0; 32], 20), Some(40));
    }
    #[test]
    fn outcomes_and_local_cleanup() {
        let marker = 0_u8;
        let high = (&marker as *const u8 as usize) + 4096;
        for (mode, count) in [(0, 40), (1, 20), (2, 0), (3, 40)] {
            let report = PublicRustWork(mode, high - 65536, high);
            assert_eq!(report.status, mode + 1);
            assert_eq!(report.comparisons, count);
            assert_eq!(report.cleared, 1);
        }
    }
    #[test]
    fn layout_and_invalid_entry() {
        assert_eq!(
            core::mem::size_of::<Report>(),
            4 * core::mem::size_of::<usize>()
        );
        for (mode, low, high) in [(4, 0, 65536), (0, 2, 1), (0, 0, 65536), (0, 0, 0)] {
            let report = PublicRustWork(mode, low, high);
            assert_eq!(
                (
                    report.status,
                    report.address,
                    report.comparisons,
                    report.cleared
                ),
                (0, 0, 0, 0)
            );
        }
    }
}
