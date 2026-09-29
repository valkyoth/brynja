//! Public-marker ABI experiment only, not a protected cryptographic API.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

#[repr(C)]
#[derive(Debug, PartialEq, Eq)]
pub struct Report {
    pub status: usize,
    pub address: usize,
    pub filled: usize,
    pub cleared: usize,
}

// This name is linked only into the separate synthetic enclave image. It accepts
// integers, never host pointers, and returns only public diagnostic values.
#[unsafe(no_mangle)]
#[inline(never)]
pub extern "C" fn PublicRustWork(mode: usize, low: usize, high: usize) -> Report {
    let mut report = Report {
        status: 0,
        address: 0,
        filled: 0,
        cleared: 0,
    };
    if mode > 3 {
        return report;
    }
    let mut marker = [0_u8; 1024];
    let address = marker.as_ptr() as usize;
    if high < low || high - low != 65536 || address < low || address > high - 1024 {
        return report;
    }
    report.address = address;
    // 0: success; 1: cancellation halfway; 2: pre-work rejection;
    // 3: post-write operation error. Each is distinct from a cleanup failure.
    let count = match mode {
        0 | 3 => 1024,
        1 => 512,
        _ => 0,
    };
    for byte in marker.iter_mut().take(count) {
        // SAFETY: exclusive reference to one initialized local-array byte.
        unsafe { core::ptr::write_volatile(byte, 0xa5) };
    }
    for byte in marker.iter().take(count) {
        // SAFETY: shared reference to one initialized local-array byte.
        if unsafe { core::ptr::read_volatile(byte) } != 0xa5 {
            return report;
        }
    }
    report.filled = count;
    for byte in &mut marker {
        if !cfg!(probe_skip_rust_clear) {
            // SAFETY: exclusive reference to one initialized local-array byte.
            unsafe { core::ptr::write_volatile(byte, 0) };
        }
    }
    let mut residue = 0_u8;
    for byte in &marker {
        // SAFETY: shared reference to one initialized local-array byte.
        residue |= unsafe { core::ptr::read_volatile(byte) };
    }
    report.cleared = usize::from(residue == 0);
    if residue == 0 {
        report.status = mode + 1;
    }
    if cfg!(probe_wrong_rust_result) {
        report.status = 99;
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;

    // Test-only enclosure of this test thread's stack. Native capture obtains
    // independently guarded/locked bounds and checks the actual Rust address.
    fn bounds() -> (usize, usize) {
        let local = 0_u8;
        let high = (&local as *const u8 as usize) + 4096;
        (high - 65536, high)
    }

    #[test]
    fn c_layout_is_four_pointer_width_words() {
        assert_eq!(
            core::mem::size_of::<Report>(),
            4 * core::mem::size_of::<usize>()
        );
        assert_eq!(
            core::mem::align_of::<Report>(),
            core::mem::align_of::<usize>()
        );
        assert_eq!(
            core::mem::offset_of!(Report, address),
            core::mem::size_of::<usize>()
        );
        assert_eq!(
            core::mem::offset_of!(Report, filled),
            2 * core::mem::size_of::<usize>()
        );
        assert_eq!(
            core::mem::offset_of!(Report, cleared),
            3 * core::mem::size_of::<usize>()
        );
    }

    #[test]
    fn every_fixed_outcome_checks_complete_local_clearing() {
        let (low, high) = bounds();
        for mode in 0..4 {
            let result = PublicRustWork(mode, low, high);
            assert_eq!(result.status, mode + 1);
            assert!(result.address >= low && result.address <= high - 1024);
            assert_eq!(
                result.filled,
                match mode {
                    0 | 3 => 1024,
                    1 => 512,
                    _ => 0,
                }
            );
            assert_eq!(result.cleared, 1);
        }
    }

    #[test]
    fn malformed_mode_or_geometry_cannot_report_execution() {
        for (mode, low, high) in [
            (4, 0, 65536),
            (usize::MAX, 0, 65536),
            (0, 1, 0),
            (0, 0, 0),
            (0, 0, 65536),
            (0, 0, usize::MAX),
        ] {
            assert_eq!(
                PublicRustWork(mode, low, high),
                Report {
                    status: 0,
                    address: 0,
                    filled: 0,
                    cleared: 0
                }
            );
        }
    }
}
