//! Focused emitted-code probes, not whole-composition cleanup qualification.
#![no_std]
#![forbid(unsafe_code)]

pub use brynja_mac_hmac::Error;

// Compile the actual runtime scratch implementation, not a copied reimplementation.
#[path = "../../../crates/brynja-mac-hmac/src/scratch.rs"]
mod scratch;

macro_rules! probe {
    ($name:ident, $size:literal) => {
        #[inline(never)]
        pub fn $name(input: &[u8; $size]) -> Result<(), Error> {
            let mut owner = scratch::Scratch::<$size>::new();
            brynja_core::copy_secret_region(owner.prefix($size)?, input)?;
            // Borrow only: keep the populated owner observable without moving it.
            core::hint::black_box(&mut owner);
            Ok(())
        }
    };
}

probe!(scratch_1, 1);
probe!(scratch_64, 64);
probe!(scratch_144, 144);

/// A non-inlined observer can unwind after seeing populated scratch.
#[inline(never)]
pub fn scratch_unwind(input: &[u8; 64], observer: fn(&[u8])) -> Result<(), Error> {
    let mut owner = scratch::Scratch::<64>::new();
    brynja_core::copy_secret_region(owner.prefix(64)?, input)?;
    observer(&owner.0);
    Ok(())
}

/// Exercise the actual reference-based pad transform before owner destruction.
#[inline(never)]
pub fn scratch_mask(input: &[u8; 144]) -> Result<(), Error> {
    let mut owner = scratch::Scratch::<144>::new();
    brynja_core::copy_secret_region(owner.prefix(144)?, input)?;
    scratch::mask_pad(&mut owner.0, 0x36)?;
    core::hint::black_box(&mut owner);
    Ok(())
}
