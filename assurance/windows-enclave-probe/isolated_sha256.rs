//! Package 08A PUBLIC-vector canary, not a shipping secret API or qualification.
#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

use brynja_hash_sha2::hardened_in_place::Sha256Workspace;

#[cfg(not(test))]
unsafe extern "C" {
    fn PublicProbeAbort() -> !;
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_: &core::panic::PanicInfo<'_>) -> ! {
    // SAFETY: the linked fixture supplies a nonreturning fast-fail boundary.
    unsafe { PublicProbeAbort() }
}

fn compute(input: &mut [u8; 1024], length: usize, output: &mut [u8; 32]) -> usize {
    let mut workspace = Sha256Workspace::new();
    let mut staging = [0_u8; 32];
    let result = if let Some(message) = input.get(..length) {
        workspace.with(|mut state| {
            state.update(message)?;
            let secret = state.finalize_secret(&mut staging)?;
            // Explicit declassification for this PUBLIC-vector experiment only.
            output.copy_from_slice(secret.expose());
            Ok::<(), brynja_hash_sha2::HardenedSha2Error>(())
        }).is_ok()
    } else {
        false
    };
    let _ = brynja_core::clear_owned_region(input);
    if !result {
        let _ = brynja_core::clear_owned_region(output);
    }
    usize::from(result)
}

/// # Safety
/// The single-thread/reentry-guarded C fixture supplies distinct, fully initialized
/// enclave-owned arrays, valid exclusively for this call. No host pointer crosses
/// this boundary. C does not inspect either range until this function returns.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn IsolatedSha256(
    input: *mut [u8; 1024], length: usize, output: *mut [u8; 32],
) -> usize {
    // SAFETY: enforced by the only C caller's fixed, separate staging objects.
    compute(unsafe { &mut *input }, length, unsafe { &mut *output })
}

#[cfg(test)]
mod tests {
    use super::compute;

    #[test]
    fn known_digest_and_full_input_retirement() {
        let mut input = [0xa5; 1024];
        input[..3].copy_from_slice(b"abc");
        let mut output = [0xcc; 32];
        assert_eq!(compute(&mut input, 3, &mut output), 1);
        assert_eq!(output, [0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
            0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03,
            0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad]);
        assert_eq!(input, [0; 1024]);
    }

    #[test]
    fn rejection_clears_complete_input_and_output() {
        for length in [1025, usize::MAX] {
            let mut input = [0xa5; 1024];
            let mut output = [0xcc; 32];
            assert_eq!(compute(&mut input, length, &mut output), 0);
            assert_eq!(input, [0; 1024]);
            assert_eq!(output, [0; 32]);
        }
    }
}
