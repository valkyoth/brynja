//! Explicit Linux RV64 Poly1305 execution; no automatic portable fallback.
#![allow(unsafe_code)]

use core::{hint::black_box, marker::PhantomData};
mod kernel;

/// Host lacks usable RVV, or this handle failed startup or was interrupted.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Error {
    /// Linux did not confirm both hardware V and permission for this thread.
    Unavailable,
    /// Terminal for this handle.
    Quarantined,
}

/// Thread-local required-native capability. The OS must keep the advertised
/// ISA usable on every CPU where this thread runs. This does not pin a CPU.
pub struct Rvv {
    ready: bool,
    local: PhantomData<*mut ()>,
}

// Linux UAPI: only bits 0..1 describe this thread *now*. Next-exec and
// inheritance flags are not permissions. Errors must never pass the mask.
fn thread_enabled(control: core::ffi::c_int) -> bool {
    control >= 0 && control & 3 == 2
}

impl Rvv {
    /// Detect RVV and check two consecutive four-block groups against a
    /// fixed, independently computed answer before admitting caller data.
    pub fn probe() -> Result<Self, Error> {
        unsafe extern "C" {
            fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
            fn prctl(option: core::ffi::c_int, ...) -> core::ffi::c_int;
        }
        // SAFETY: numeric AT_HWCAP query. A missing value denies V.
        if unsafe { getauxval(16) } & (1 << (b'V' - b'A')) == 0 {
            return Err(Error::Unavailable);
        }
        let zero: core::ffi::c_ulong = 0;
        // SAFETY: PR_RISCV_V_GET_CONTROL is read-only; four unsigned-long
        // zero arguments, no pointers. Never enable V or change process policy.
        let control = unsafe { prctl(70, zero, zero, zero, zero) };
        if !thread_enabled(control) {
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
        // Twelve maximal full blocks, with maximal clamped r and initial limbs.
        let mut h = [((1_u64 << 26) - 1).to_le_bytes(); 5];
        owner.absorb_groups(
            black_box(&mut h),
            black_box(&[0xff; 16]),
            black_box(&[[0xff; 64]; 3]),
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
        blocks: &[[u8; 64]],
    ) -> Result<(), Error> {
        self.check()?;
        self.ready = false;
        // SAFETY: probe is the sole constructor and checked host RVV before
        // running even the startup test. No raw pointers cross the boundary.
        *acc = unsafe { kernel::absorb(acc, r, blocks) };
        self.ready = true;
        Ok(())
    }
}

#[cfg(test)]
#[test]
fn only_current_on_admits_vector_execution() {
    for other in [0, 4, 8, 12, 16, 20, 24, 28] {
        for current in 0..=3 {
            assert_eq!(thread_enabled(other | current), current == 2);
        }
    }
    assert!(!thread_enabled(-1));
    assert!(!thread_enabled(-2));
}
