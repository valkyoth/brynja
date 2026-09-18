//! Eight AVX2 lanes behind one opaque secret-computation boundary.
#![allow(unsafe_code)]
use super::{Md5BackendError, constants::HARDENED_CONSTANTS, scratch::Scratch};

mod kernel;

const _: () = {
    assert!(core::mem::size_of::<Scratch>() == 864);
    assert!(core::mem::align_of::<Scratch>() == 1);
    assert!(core::mem::offset_of!(Scratch, initial) == 0);
    assert!(core::mem::offset_of!(Scratch, words) == 128);
    assert!(core::mem::offset_of!(Scratch, work) == 640);
    assert!(core::mem::offset_of!(Scratch, temporary) == 768);
};

#[target_feature(enable = "avx2")]
#[inline(never)]
pub(super) unsafe fn compress_secret(s: &mut Scratch) -> Result<(), Md5BackendError> {
    // SAFETY: Private dispatch retains lifetime-wide feature authority.
    // repr(C) and these assertions bind all initialized byte fields without
    // padding. The exclusive reborrow cannot escape. Only packed output
    // survives; non-output scratch and kernel working registers clear before
    // normal return. Caller packing and output handling remain separate.
    unsafe {
        kernel::compress(
            &mut *core::ptr::from_mut(s).cast::<[u8; 864]>(),
            &HARDENED_CONSTANTS,
        );
    }
    Ok(())
}
