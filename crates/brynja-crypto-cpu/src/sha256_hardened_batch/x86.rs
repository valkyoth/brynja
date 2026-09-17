//! Eight AVX2 lanes behind one opaque secret-computation boundary.
#![allow(unsafe_code)]
use super::{Error, Workspace};

mod secret;

const _: () = {
    assert!(core::mem::size_of::<Workspace>() == 2752);
    assert!(core::mem::offset_of!(Workspace, initial) == 0);
    assert!(core::mem::offset_of!(Workspace, schedule) == 256);
    assert!(core::mem::offset_of!(Workspace, work) == 2304);
    assert!(core::mem::offset_of!(Workspace, temporary) == 2560);
};

#[target_feature(enable = "avx2")]
#[inline(never)]
pub(super) unsafe fn compress_secret(s: &mut Workspace) -> Result<(), Error> {
    // SAFETY: The private dispatcher retains lifetime-wide AVX2
    // authority. repr(C) and the assertions above bind the initialized byte
    // fields to the exact kernel layout. The exclusive reborrow covers only
    // those fields, has no padding, and cannot escape the call. The kernel
    // retains only packed output and clears its own working registers and
    // non-output scratch before normal return; caller packing is separate.
    unsafe {
        secret::compress(
            &mut *core::ptr::from_mut(s).cast::<[u8; 2752]>(),
            &crate::sha256_schedule::ROUND_CONSTANTS,
        );
    }
    Ok(())
}
