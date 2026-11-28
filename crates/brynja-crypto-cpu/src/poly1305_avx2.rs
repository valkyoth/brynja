//! Explicit Linux x86-64 Poly1305 execution; no automatic portable fallback.
#![allow(unsafe_code)]

use core::{hint::black_box, marker::PhantomData};
mod kernel;

/// Host lacks usable AVX2, or this handle failed startup or was interrupted.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// No AVX2 support advertised by the process environment.
    Unavailable,
    /// Terminal for this handle.
    Quarantined,
}

/// Thread-local required-native capability. The OS must keep the advertised
/// ISA usable on every CPU where this thread runs. This does not pin a CPU.
pub struct Avx2 {
    ready: bool,
    local: PhantomData<*mut ()>,
}

impl Avx2 {
    /// Detect AVX2 and check two consecutive four-block groups against a
    /// fixed, independently computed answer before admitting caller data.
    pub fn probe() -> Result<Self, Error> {
        if !std::is_x86_feature_detected!("avx2") {
            return Err(Error::Unavailable);
        }
        let mut owner = Self {
            ready: true,
            local: PhantomData,
        };
        let r = 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100_u128.to_le_bytes();
        let mut h = [7_u64, 0, 0, 0, 0].map(u64::to_le_bytes);
        let mut next = 0_u8;
        let blocks = [[(); 64]; 2].map(|row| {
            row.map(|()| {
                let byte = next;
                next = next.wrapping_add(1);
                byte
            })
        });
        owner.absorb_groups(black_box(&mut h), black_box(&r), black_box(&blocks))?;
        if h.map(u64::from_le_bytes) != [62060317, 5262367, 22716242, 12841259, 60432388] {
            return Err(Error::Quarantined);
        }
        Ok(owner)
    }

    /// Whether this handle permits a new message, update, or finish.
    pub fn check(&self) -> Result<(), Error> {
        if self.ready {
            Ok(())
        } else {
            Err(Error::Quarantined)
        }
    }

    /// Low-level full groups only, without finalization. Each accumulator
    /// slot is a little-endian radix-2^26 limb; unused high bits are ignored.
    /// The raw multiplier is clamped here, never its powers. The caller owns
    /// its buffers. Prefer the one-time-key API in the MAC crate.
    #[doc(hidden)]
    pub fn absorb_groups(
        &mut self,
        acc: &mut [[u8; 8]; 5],
        r: &[u8; 16],
        blocks: &[[u8; 64]],
    ) -> Result<(), Error> {
        self.check()?;
        self.ready = false;
        // SAFETY: probe is the sole constructor and checked host AVX2 before
        // running even the startup test. No raw pointers cross the boundary.
        *acc = unsafe { kernel::absorb(acc, r, blocks) };
        self.ready = true;
        Ok(())
    }
}
