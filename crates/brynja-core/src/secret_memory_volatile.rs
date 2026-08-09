//! Isolated volatile-store implementation for owned-region clearing.
//!
//! This is the only production module admitted to contain unsafe Rust. The
//! safe caller proves exclusive access and a live Rust allocation by passing a
//! mutable slice. The implementation derives every raw pointer from each live
//! exclusive byte reference and never performs pointer arithmetic.

use core::sync::atomic::{Ordering, compiler_fence};

/// Overwrites every byte in one exclusively borrowed Rust allocation.
#[inline(never)]
#[allow(unsafe_code)]
pub(crate) fn zeroize_region_volatile(region: &mut [u8]) {
    for byte in region {
        let destination = core::ptr::from_mut(byte);
        // SAFETY: `destination` comes from a live, aligned, exclusive `&mut
        // u8`, remains within that Rust allocation, and is written exactly
        // once before the exclusive borrow advances to the next byte.
        unsafe { core::ptr::write_volatile(destination, 0_u8) };
    }
    // This is a compiler barrier, not a cache flush or inter-thread primitive.
    compiler_fence(Ordering::SeqCst);
}
