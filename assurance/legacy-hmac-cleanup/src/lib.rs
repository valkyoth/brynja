//! Exact production Scratch probes, not complete caller/worker-frame erasure.
#![no_std]
#![forbid(unsafe_code)]

pub use brynja_legacy_hmac::Error;

#[path = "../../../crates/brynja-legacy-hmac/src/scratch.rs"]
mod scratch;

macro_rules! probe {
    ($name:ident, $size:literal) => {
        #[inline(never)]
        pub fn $name(input: &[u8; $size]) -> Result<(), Error> {
            let mut owner = scratch::Scratch::<$size>::new();
            brynja_core::copy_secret_region(owner.prefix($size)?, input)?;
            core::hint::black_box(&mut owner);
            Ok(())
        }
    };
}

// Comparison accumulator, digest staging, and the SHA-1/MD5 HMAC pad.
probe!(scratch_1, 1);
probe!(scratch_20, 20);
probe!(scratch_64, 64);

#[inline(never)]
pub fn scratch_unwind(input: &[u8; 64], observer: fn(&[u8])) -> Result<(), Error> {
    let mut owner = scratch::Scratch::<64>::new();
    brynja_core::copy_secret_region(owner.prefix(64)?, input)?;
    observer(&owner.0);
    Ok(())
}

#[inline(never)]
pub fn scratch_mask(input: &[u8; 64]) -> Result<(), Error> {
    let mut owner = scratch::Scratch::<64>::new();
    brynja_core::copy_secret_region(owner.prefix(64)?, input)?;
    scratch::mask(&mut owner.0, 0x36)?;
    core::hint::black_box(&mut owner);
    Ok(())
}
