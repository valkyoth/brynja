//! Exact PUBLIC artifact admission. Not signature verification or attestation.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

const MAX_IMAGE: usize = 16 * 1024 * 1024;
// Previously reviewed development image, not a production image allowlist.
const EXPECTED: [u8; 32] = [
    0xa2, 0xa3, 0x1e, 0xeb, 0xf0, 0x42, 0xe3, 0x10, 0xa7, 0x6b, 0x36, 0x3e, 0xb0, 0xfa, 0x3b, 0xf2,
    0x4c, 0xd7, 0xd9, 0xfe, 0x81, 0xbc, 0xde, 0xc0, 0x35, 0x3b, 0x95, 0xf4, 0x39, 0x2d, 0xe8, 0xcc,
];

fn matches_pin(bytes: &[u8], expected: &[u8; 32]) -> bool {
    if !(512..=MAX_IMAGE).contains(&bytes.len()) {
        return false;
    }
    let Ok(digest) = brynja_hash_sha2::sha256(bytes) else {
        return false;
    };
    // Artifact bytes and their identity are public, not a secret comparison.
    digest.as_bytes() == expected
}

/// # Safety
/// The private C file adapter supplies a live immutable buffer of exactly length
/// bytes for this synchronous call. No pointer is saved or dereferenced on error.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn ProbeImageCheck(bytes: *const u8, length: usize) -> i32 {
    if bytes.is_null() || !(512..=MAX_IMAGE).contains(&length) {
        return 0;
    }
    // SAFETY: private adapter owns the complete bounded public file buffer.
    let bytes = unsafe { core::slice::from_raw_parts(bytes, length) };
    i32::from(matches_pin(bytes, &EXPECTED))
}

#[cfg(not(test))]
unsafe extern "C" {
    fn ProbeImageAbort() -> !;
}
#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: private adapter aborts; fatal termination is not cleanup evidence.
    unsafe { ProbeImageAbort() }
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    #[test]
    fn whole_artifact_hash_not_prefix_or_length() {
        let input = [0x55; 512];
        let expected = *brynja_hash_sha2::sha256(&input).unwrap().as_bytes();
        assert!(matches_pin(&input, &expected));
        for index in 0..input.len() {
            let mut changed = input;
            changed[index] ^= 1;
            assert!(!matches_pin(&changed, &expected));
        }
        assert!(!matches_pin(&input, &EXPECTED));
        assert!(!matches_pin(&[0x55; 513], &expected));
        assert!(!matches_pin(&input[..511], &expected));
    }
    #[test]
    fn null_and_oversized_ffi_reject_before_access() {
        // SAFETY: null and invalid lengths must be rejected without dereference.
        for length in [0, 511, 512, MAX_IMAGE, usize::MAX] {
            assert_eq!(unsafe { ProbeImageCheck(core::ptr::null(), length) }, 0);
        }
        let byte = 0u8;
        assert_eq!(unsafe { ProbeImageCheck(&byte, MAX_IMAGE + 1) }, 0);
    }
    #[test]
    fn upper_size_bound_fails_closed() {
        let input = std::vec![0; MAX_IMAGE + 1];
        assert!(!matches_pin(&input, &EXPECTED));
    }
}
