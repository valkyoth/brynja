//! Explicit little-endian AArch64 NEON Poly1305 execution; no automatic portable fallback.
#![allow(unsafe_code)]

use core::{hint::black_box, marker::PhantomData};
mod kernel;

/// The required static NEON backend failed startup or was interrupted.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// Terminal for this handle.
    Quarantined,
}

/// Thread-local required-native capability. The OS must keep the advertised
/// ISA usable on every CPU where this thread runs. This does not pin a CPU.
pub struct Neon {
    ready: bool,
    local: PhantomData<*mut ()>,
}

impl Neon {
    /// On a NEON build target, check four consecutive two-block groups against a
    /// fixed, independently computed answer before admitting caller data.
    pub fn probe() -> Result<Self, Error> {
        // This static backend is compiled only for NEON-enabled AArch64 targets.
        let mut owner = Self {
            ready: true,
            local: PhantomData,
        };
        let r = 0x0f0e_0d0c_0b0a_0908_0706_0504_0302_0100_u128.to_le_bytes();
        let mut h = [7_u64, 0, 0, 0, 0].map(u64::to_le_bytes);
        let mut next = 0_u8;
        let blocks = [[(); 32]; 4].map(|row| {
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
        // Twelve maximal full blocks, with maximal clamped r and initial limbs.
        let mut h = [((1_u64 << 26) - 1).to_le_bytes(); 5];
        owner.absorb_groups(
            black_box(&mut h),
            black_box(&[0xff; 16]),
            black_box(&[[0xff; 32]; 6]),
        )?;
        if h.map(u64::from_le_bytes) != [6376392, 44811416, 8450298, 23877029, 21726864] {
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
    /// slot is a little-endian radix-2^26 coefficient; excess bits are
    /// carried modulo 2^130-5. Returned limbs fit in 26 bits.
    /// The raw multiplier is clamped here, never its powers. The caller owns
    /// its buffers. Prefer the one-time-key API in the MAC crate.
    #[doc(hidden)]
    pub fn absorb_groups(
        &mut self,
        acc: &mut [[u8; 8]; 5],
        r: &[u8; 16],
        blocks: &[[u8; 32]],
    ) -> Result<(), Error> {
        self.check()?;
        self.ready = false;
        // SAFETY: the module requires NEON in the compilation target before
        // running even the startup test. No raw pointers cross the boundary.
        *acc = unsafe { kernel::absorb(acc, r, blocks) };
        self.ready = true;
        Ok(())
    }
}
