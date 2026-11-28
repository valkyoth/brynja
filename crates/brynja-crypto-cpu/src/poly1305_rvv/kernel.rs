//! Four consecutive full blocks, in radix 2^26 modulo 2^130-5.
use brynja_core::clear_owned_region;
// A private, Rust-mangled symbol allows independently versioned crates to
// coexist. The scalar C ABI supplies a0..a2; no callee-saved registers are used.
#[unsafe(naked)]
unsafe extern "C" fn columns(
    words: *const [[u32; 4]; 5],
    weights: *const Weights,
    sum: *mut [u64; 5],
) {
    core::arch::naked_asm!(
        r#"
// Four-block column kernel; standard scalar ABI, Linux RV64 with full V.
// a0 = 5 x 4 u32 message limbs; a1 = 9 x 4 u32 weights; a2 = 5 u64 sums.
.option push
.option arch, +v
    vsetivli zero, 4, e32, m1, ta, ma
    .irp r,0,1,2,3,4
        vle32.v v\r, (a0)
        addi a0, a0, 16
    .endr
    .irp r,5,6,7,8,9,10,11,12,13
        vle32.v v\r, (a1)
        addi a1, a1, 16
    .endr
    .macro column dest,a,b,c,d,e
        vwmulu.vv \dest,v0,\a
        vwmaccu.vv \dest,v1,\b
        vwmaccu.vv \dest,v2,\c
        vwmaccu.vv \dest,v3,\d
        vwmaccu.vv \dest,v4,\e
    .endm
    // v5..9 contain r,s,t,u,v; v10..13 contain 5s,5t,5u,5v.
    column v16,v5,v13,v12,v11,v10
    column v18,v6,v5,v13,v12,v11
    column v20,v7,v6,v5,v13,v12
    column v22,v8,v7,v6,v5,v13
    column v24,v9,v8,v7,v6,v5
    .purgem column
    vsetivli zero, 4, e64, m2, ta, ma
    vmv.s.x v28, zero
    .irp r,16,18,20,22,24
        vredsum.vs v30, v\r, v28
        vmv.x.s t0, v30
        sd t0, 0(a2)
        addi a2, a2, 8
    .endr
    ret
.option pop
"#,
        options(raw)
    );
}

use crate::poly1305_field::{F, Scratch, accumulator, limbs, product, reduce};

fn low_word([a, b, c, d, ..]: [u8; 8]) -> u32 {
    u32::from_le_bytes([a, b, c, d])
}

type Weights = [[u32; 4]; 9];

struct Table<'a>(&'a mut Weights);
impl Drop for Table<'_> {
    fn drop(&mut self) {
        // SAFETY: a contiguous initialized u32 array, exclusively borrowed;
        // clearing every byte leaves a valid value.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::from_mut(self.0).cast::<u8>(),
                core::mem::size_of::<Weights>(),
            )
        };
        let _ = clear_owned_region(bytes);
    }
}

// SAFETY: caller admits Linux HWCAP V and maintains usable ISA through use.
pub(super) unsafe fn absorb(
    acc: &[[u8; 8]; 5],
    raw: &[u8; 16],
    blocks: &[[u8; 64]],
) -> [[u8; 8]; 5] {
    let mut h = accumulator(acc);
    let mut powers = Scratch([[[0; 8]; 5]; 4]);
    let [r4, r3, r2, r1] = &mut powers.0;
    *r1 = limbs(u128::from_le_bytes(*raw) & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff)
        .map(u64::to_le_bytes);
    *r2 = product(r1.map(u64::from_le_bytes), r1.map(u64::from_le_bytes)).map(u64::to_le_bytes);
    *r3 = product(r2.map(u64::from_le_bytes), r1.map(u64::from_le_bytes)).map(u64::to_le_bytes);
    *r4 = product(r2.map(u64::from_le_bytes), r2.map(u64::from_le_bytes)).map(u64::to_le_bytes);
    let mut storage = [[0; 4]; 9];
    let table = Table(&mut storage);
    let [r, s, t, u, v, s5, t5, u5, v5] = table.0;
    let [a, b, c, d] = &powers.0;
    for ((((row, a), b), c), d) in [r, &mut *s, &mut *t, &mut *u, &mut *v]
        .into_iter()
        .zip(a)
        .zip(b)
        .zip(c)
        .zip(d)
    {
        *row = [*a, *b, *c, *d].map(low_word);
    }
    for (dst, src) in [(s5, s), (t5, t), (u5, u), (v5, v)] {
        *dst = src.map(|x| x.wrapping_mul(5)); // <5*2^26
    }
    drop(powers);
    for block in blocks {
        let [a, b, c, d] = block.as_chunks::<16>().0 else {
            unreachable!("four full blocks")
        };
        let [mut a, b, c, d] = [a, b, c, d].map(|b| {
            let mut m = limbs(u128::from_le_bytes(*b));
            m[4] |= 1 << 24;
            m
        });
        for (v, x) in a.iter_mut().zip(h) {
            *v = v.wrapping_add(x); // <2*2^26
        }
        let mut words = [[0; 4]; 5];
        for ((((out, a), b), c), d) in words.iter_mut().zip(a).zip(b).zip(c).zip(d) {
            *out = [a, b, c, d].map(|x| low_word(x.to_le_bytes()));
        }
        let mut sum = [0u64; 5];
        // SAFETY: see admission above. Full V supports VL=4 at e32/m1 and
        // e64/m2. All input rows are aligned and initialized. The five u64
        // stores stay within the separate, exclusive sum; columns <200*2^52.
        unsafe {
            columns(&words, table.0, &mut sum);
        }
        h = reduce(sum);
    }
    h.map(u64::to_le_bytes)
}

#[cfg(test)]
#[test]
fn weights_cleared_on_return_and_unwind() {
    for stop in [false, true] {
        let mut weights = [[u32::MAX; 4]; 9];
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _table = Table(&mut weights);
            if stop {
                std::panic::resume_unwind(std::boxed::Box::new(()));
            }
        }));
        assert_eq!(outcome.is_err(), stop);
        assert_eq!(weights, [[0; 4]; 9]);
    }
}
