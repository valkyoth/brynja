//! Packed AVX2 Keccak behind one opaque secret-computation boundary.
#![allow(unsafe_code)]
use super::{Error, Workspace};

mod secret;

const _: () = {
    assert!(core::mem::size_of::<Workspace>() == 1920);
    assert!(core::mem::offset_of!(Workspace, state) == 0);
    assert!(core::mem::offset_of!(Workspace, columns) == 800);
    assert!(core::mem::offset_of!(Workspace, deltas) == 960);
    assert!(core::mem::offset_of!(Workspace, staging) == 1120);
};

#[target_feature(enable = "avx2")]
#[inline(never)]
pub(super) unsafe fn permute_secret(s: &mut Workspace) -> Result<(), Error> {
    // SAFETY: Private dispatch retains lifetime-wide AVX2 authority.
    // repr(C) and the assertions above bind all initialized byte fields to
    // the exact fixed kernel layout, with no padding. The exclusive reborrow
    // cannot escape; only output remains after normal return. Caller packing
    // and higher-level owner cleanup are separate obligations.
    unsafe {
        secret::permute(
            &mut *core::ptr::from_mut(s).cast::<[u8; 1920]>(),
            &crate::keccak_constants::ROUND_CONSTANTS,
        );
    }
    Ok(())
}
