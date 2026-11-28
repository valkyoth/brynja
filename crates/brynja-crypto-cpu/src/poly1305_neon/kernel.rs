//! Two consecutive full blocks, in radix 2^26 modulo 2^130-5.
use brynja_core::clear_owned_region;
use core::arch::aarch64::*;

type F = [u64; 5];
const MASK: u64 = (1 << 26) - 1;

fn limbs(mut n: u128) -> F {
    core::array::from_fn(|_| {
        let [a, b, c, d, ..] = n.to_le_bytes();
        n >>= 26;
        u64::from(u32::from_le_bytes([a, b, c, d])) & MASK
    })
}

fn reduce(mut x: F) -> F {
    // Each column (even after summing two lanes) is below 200 * 2^52.
    // Fold at bit 130; after the first fold only limb 0 can exceed MASK.
    for _ in 0..3 {
        let mut carry = 0;
        for word in &mut x {
            let n = word.wrapping_add(carry);
            *word = n & MASK;
            carry = n >> 26;
        }
        x[0] = x[0].wrapping_add(carry.wrapping_mul(5));
    }
    x
}

fn product(a: F, [r, s, t, u, v]: F) -> F {
    let [s5, t5, u5, v5] = [s, t, u, v].map(|x| x.wrapping_mul(5));
    reduce(
        [
            [r, v5, u5, t5, s5],
            [s, r, v5, u5, t5],
            [t, s, r, v5, u5],
            [u, t, s, r, v5],
            [v, u, t, s, r],
        ]
        .map(|col| {
            a.into_iter()
                .zip(col)
                .fold(0u64, |n, (x, y)| n.wrapping_add(x.wrapping_mul(y)))
        }),
    )
}

struct Scratch<const N: usize, const M: usize>([[[u8; 8]; M]; N]);
impl<const N: usize, const M: usize> Drop for Scratch<N, M> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.0.as_flattened_mut().as_flattened_mut());
    }
}

type Weights = [[uint32x2_t; 5]; 5];
struct ClearingTable<'a>(&'a mut Weights);
impl Drop for ClearingTable<'_> {
    fn drop(&mut self) {
        // SAFETY: Weights contains 25 initialized integer vectors, no
        // padding or references. The byte view is bounded by the complete
        // array and exclusively borrowed; all-zero bits are valid on return.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                core::ptr::from_mut(self.0).cast::<u8>(),
                core::mem::size_of::<Weights>(),
            )
        };
        let _ = clear_owned_region(bytes);
    }
}

#[target_feature(enable = "neon")]
fn pack(a: u64, b: u64) -> uint32x2_t {
    // Each radix limb is below 2^27, or below 5*2^26 for a wrapped weight.
    let low = |n: u64| {
        let [a, b, c, d, ..] = n.to_le_bytes();
        u32::from_le_bytes([a, b, c, d])
    };
    vset_lane_u32::<1>(low(b), vdup_n_u32(low(a)))
}

#[target_feature(enable = "neon")]
#[inline(never)]
fn group(h: F, bytes: &[u8; 32], table: &Weights) -> F {
    let [a, b] = bytes.as_chunks::<16>().0 else {
        unreachable!("two full blocks")
    };
    let [mut first, second] = [a, b].map(|m| {
        let mut x = limbs(u128::from_le_bytes(*m));
        x[4] |= 1 << 24;
        x
    });
    for (x, y) in first.iter_mut().zip(h) {
        *x = x.wrapping_add(y);
    }
    let mut words = [vdup_n_u32(0); 5];
    for ((out, a), b) in words.iter_mut().zip(first).zip(second) {
        *out = pack(a, b);
    }
    reduce(table.map(|[a, b, c, d, e]| {
        let [p, q, r, s, t] = words;
        let acc = vmull_u32(p, a);
        let acc = vmlal_u32(acc, q, b);
        let acc = vmlal_u32(acc, r, c);
        let acc = vmlal_u32(acc, s, d);
        vaddvq_u64(vmlal_u32(acc, t, e))
    }))
}

#[target_feature(enable = "neon")]
pub(super) fn absorb(acc: &[[u8; 8]; 5], raw: &[u8; 16], blocks: &[[u8; 32]]) -> [[u8; 8]; 5] {
    let mut h = acc.map(|v| u64::from_le_bytes(v) & MASK);
    let r = limbs(u128::from_le_bytes(*raw) & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff);
    let mut powers = Scratch([[[0; 8]; 5]; 2]);
    let [r2, r1] = &mut powers.0;
    *r1 = r.map(u64::to_le_bytes);
    *r2 = product(r, r).map(u64::to_le_bytes);
    let mut storage = [[vdup_n_u32(0); 5]; 5];
    let table = ClearingTable(&mut storage);
    let [a, b, c, d, e] = r2;
    let [f, g, h1, i, j] = r1;
    let [r, s, t, u, v] = [(a, f), (b, g), (c, h1), (d, i), (e, j)]
        .map(|(a, b)| pack(u64::from_le_bytes(*a), u64::from_le_bytes(*b)));
    let [s5, t5, u5, v5] = [s, t, u, v].map(|x| vadd_u32(x, vshl_n_u32::<2>(x)));
    *table.0 = [
        [r, v5, u5, t5, s5],
        [s, r, v5, u5, t5],
        [t, s, r, v5, u5],
        [u, t, s, r, v5],
        [v, u, t, s, r],
    ];
    drop(powers);
    for b in blocks {
        h = group(h, b, table.0);
    }
    h.map(u64::to_le_bytes)
}

#[cfg(test)]
#[test]
fn table_guard_clears_live_storage() {
    #[target_feature(enable = "neon")]
    fn test(unwind: bool) {
        let mut table = [[vdup_n_u32(u32::MAX); 5]; 5];
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = ClearingTable(&mut table);
            if unwind {
                std::panic::resume_unwind(std::boxed::Box::new(()));
            }
        }));
        assert_eq!(outcome.is_err(), unwind);
        for vec in table.into_iter().flatten() {
            assert_eq!(vget_lane_u64::<0>(vreinterpret_u64_u32(vec)), 0);
        }
    }
    for unwind in [false, true] {
        // SAFETY: compiled only on a NEON target.
        unsafe { test(unwind) };
    }
}
