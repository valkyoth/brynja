//! Unqualified fixed-size comparison workbench, gated by a non-Cargo cfg.
//!
//! NOT release authorization, a fault-resistant predicate or a supported public
//! API. Both operations compare all sixteen observed bytes with BOTH replicas.
//! They write two raw accumulators into caller-owned clearing storage, without
//! returning a Boolean. Intermediate differences can disclose information:
//! callers must not expose them, must retain cleanup guards, and must not treat
//! one comparison result as authority to release output.
//!
//! Baseline x86-64 and little-endian AArch64 use separate opaque implementations;
//! other targets and Miri/Kani use portable functional models. No target is
//! admitted by this module. Independence of callers/decoding, wide authorization,
//! flags, latches, C1/DC1 and final-linked fault simulation remain unfinished.
#![allow(unsafe_code)]

mod guarded_copy;
pub use guarded_copy::{tentative_copy_16, uses_guarded_copy_candidate};

#[cfg(all(
    not(any(miri, kani)),
    any(
        target_arch = "x86_64",
        all(target_arch = "aarch64", target_endian = "little")
    )
))]
mod opaque;

/// Whether this build selects the opaque candidate, NOT whether it is qualified.
pub const fn uses_opaque_candidate() -> bool {
    cfg!(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))
}

/// Full forward comparisons: writes OR-of-XOR differences for primary/secondary.
/// Each output byte is zero exactly when that replica matches all observed bytes.
/// Inputs may alias each other; the exclusive output cannot alias an input.
/// The output is overwritten completely and must be kept in clearing storage.
#[inline(never)]
pub fn forward_16(
    output: &mut [u8; 2],
    observed: &[u8; 16],
    primary: &[u8; 16],
    secondary: &[u8; 16],
) {
    #[cfg(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    // SAFETY: Safe fixed-size borrows prove 2 writable and 16 readable bytes
    // per pointer, output disjointness, lifetime and bounds; inputs may alias.
    unsafe {
        opaque::forward(
            output.as_mut_ptr(),
            observed.as_ptr(),
            primary.as_ptr(),
            secondary.as_ptr(),
        );
    }
    #[cfg(not(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    )))]
    model_forward(output, observed, primary, secondary);
}

/// Full reverse comparisons: writes AND-of-XNOR masks for primary/secondary.
/// Each output byte is 0xff exactly when that replica matches all observed bytes.
/// This uses fresh loads and separate accumulation, not the forward result.
/// Ownership, aliasing and qualification limitations match [`forward_16`].
#[inline(never)]
pub fn reverse_16(
    output: &mut [u8; 2],
    observed: &[u8; 16],
    primary: &[u8; 16],
    secondary: &[u8; 16],
) {
    #[cfg(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))]
    // SAFETY: Same fixed-size, live and disjoint output/input borrows as forward.
    unsafe {
        opaque::reverse(
            output.as_mut_ptr(),
            observed.as_ptr(),
            primary.as_ptr(),
            secondary.as_ptr(),
        );
    }
    #[cfg(not(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    )))]
    model_reverse(output, observed, primary, secondary);
}

#[cfg(any(
    test,
    not(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))
))]
fn model_forward(
    output: &mut [u8; 2],
    observed: &[u8; 16],
    primary: &[u8; 16],
    secondary: &[u8; 16],
) {
    let [a, b] = output;
    *a = 0;
    *b = 0;
    for ((actual, p), s) in observed.iter().zip(primary).zip(secondary) {
        *a |= *actual ^ *p;
        *b |= *actual ^ *s;
    }
}

#[cfg(any(
    test,
    not(all(
        not(any(miri, kani)),
        any(
            target_arch = "x86_64",
            all(target_arch = "aarch64", target_endian = "little")
        )
    ))
))]
fn model_reverse(
    output: &mut [u8; 2],
    observed: &[u8; 16],
    primary: &[u8; 16],
    secondary: &[u8; 16],
) {
    let [a, b] = output;
    *a = 0xff;
    *b = 0xff;
    for ((actual, p), s) in observed.iter().zip(primary).zip(secondary).rev() {
        *a &= !(*actual ^ *p);
        *b &= !(*actual ^ *s);
    }
}

#[cfg(test)]
mod tests;
