//! Unpublished Linux RV64 V candidate; never linked into the cipher crate.
use brynja_cipher_chacha::{ChaCha20, Error};

#[repr(C, align(16))]
struct State([[[u8; 4]; 4]; 16]);

impl Drop for State {
    fn drop(&mut self) {
        let _ = brynja_core::clear_owned_region(self.0.as_flattened_mut().as_flattened_mut());
    }
}

pub use native::available;

// Private proof of Linux V admission. Never execute a candidate on a CPU
// selected by name alone. As with other hosted ISA detection, the OS must
// continue to make the advertised ISA available while the request is running.
struct Vector;

impl Vector {
    fn detect() -> Option<Self> {
        available().then_some(Self)
    }
}

#[allow(unsafe_code)]
mod native {
    use super::{State, Vector};
    core::arch::global_asm!(include_str!("rvv.S"), options(raw));
    pub fn available() -> bool {
        unsafe extern "C" {
            fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
        }
        // SAFETY: Linux ELF getauxval(AT_HWCAP) takes only a numeric selector.
        // Zero (including a missing entry) refuses V. Never change OS policy.
        (unsafe { getauxval(16) }) & (1 << (b'V' - b'A')) != 0
    }

    impl Vector {
        pub(super) fn permute(&self, state: &mut State) {
            unsafe extern "C" {
                fn brynja_probe_rvv_rounds(state: *mut State);
            }
            // SAFETY: this private token requires OS-advertised V. Full V supports
            // four e32,m1 lanes. State is aligned, writable and exclusively borrowed;
            // the leaf loads and stores exactly its sixteen 16-byte columns. No
            // pointer escapes or stack writes. Only scalar-ABI temporaries change.
            unsafe { brynja_probe_rvv_rounds(state) }
        }
    }
}

fn xor4(v: &Vector, key: &[u8; 32], nonce: &[u8; 12], lanes: [u32; 4], bytes: &mut [u8; 256]) {
    let mut initial = State([[[0; 4]; 4]; 16]);
    for (col, word) in initial.0.iter_mut().zip(
        b"expand 32-byte k"
            .as_chunks::<4>()
            .0
            .iter()
            .chain(key.as_chunks::<4>().0),
    ) {
        *col = [*word; 4];
    }
    initial.0[12] = lanes.map(u32::to_le_bytes);
    for (col, word) in initial.0[13..].iter_mut().zip(nonce.as_chunks::<4>().0) {
        *col = [*word; 4];
    }
    let mut work = State(initial.0);
    v.permute(&mut work);
    let out = bytes.as_chunks_mut::<4>().0;
    for (i, (sums, bases)) in work.0.iter().zip(&initial.0).enumerate() {
        for ((dst, sum), base) in out.iter_mut().skip(i).step_by(16).zip(sums).zip(bases) {
            let stream = u32::from_le_bytes(*sum).wrapping_add(u32::from_le_bytes(*base));
            *dst = (u32::from_le_bytes(*dst) ^ stream).to_le_bytes();
        }
    }
}

/// Evidence only: process one aligned-start request, None if V is unavailable.
pub fn try_record(
    key: &[u8; 32],
    nonce: [u8; 12],
    first: u32,
    data: &mut [u8],
) -> Option<Result<(), Error>> {
    let v = Vector::detect()?;
    let scalar = ChaCha20::new(key, nonce, first);
    if data.len() as u64 > scalar.remaining_bytes() {
        return Some(Err(Error::Exhausted));
    }
    let (groups, tail) = data.as_chunks_mut::<256>();
    let mut starts = (first..=u32::MAX).step_by(4);
    for group in groups {
        let Some(end) = starts.next().and_then(|n| n.checked_add(3)) else {
            return Some(Err(Error::Exhausted));
        };
        xor4(&v, key, &nonce, [end - 3, end - 2, end - 1, end], group);
    }
    if !tail.is_empty() {
        let start = starts.next().expect("preflight covers tail");
        return Some(ChaCha20::new(key, nonce, start).apply_keystream_in_place(tail));
    }
    Some(Ok(()))
}

pub fn record(key: &[u8; 32], nonce: [u8; 12], first: u32, data: &mut [u8]) -> Result<(), Error> {
    try_record(key, nonce, first, data).expect("forced RVV fixture requires OS-advertised V")
}
