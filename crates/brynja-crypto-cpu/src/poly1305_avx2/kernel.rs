//! Four consecutive full blocks, in radix 2^26 modulo 2^130-5.
use brynja_core::clear_owned_region;
use core::arch::x86_64::*;

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
    // Each column (even after summing four lanes) is below 200 * 2^52.
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

#[target_feature(enable = "avx2")]
fn pack(bytes: [[u8; 8]; 4]) -> __m256i {
    let [a, b, c, d] = bytes.map(i64::from_le_bytes);
    _mm256_set_epi64x(d, c, b, a)
}

type Weights = [[__m256i; 5]; 5];

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

#[target_feature(enable = "avx2")]
#[inline(never)]
fn group(h: F, block: &[u8; 64], table: &Weights) -> F {
    let [a, b, c, d] = block.as_chunks::<16>().0 else {
        unreachable!("64 bytes = four blocks")
    };
    let [mut first, b, c, d] = [a, b, c, d].map(|m| {
        let mut words = limbs(u128::from_le_bytes(*m));
        words[4] |= 1 << 24;
        words
    });
    for (x, y) in first.iter_mut().zip(h) {
        *x = x.wrapping_add(y);
    }
    let mut words = [_mm256_setzero_si256(); 5];
    for ((((out, a), b), c), d) in words.iter_mut().zip(first).zip(b).zip(c).zip(d) {
        *out = pack([a, b, c, d].map(u64::to_le_bytes));
    }
    reduce(table.map(|col| {
        let sum = words
            .into_iter()
            .zip(col)
            .fold(_mm256_setzero_si256(), |acc, (x, y)| {
                _mm256_add_epi64(acc, _mm256_mul_epu32(x, y))
            });
        [
            _mm256_extract_epi64::<0>(sum),
            _mm256_extract_epi64::<1>(sum),
            _mm256_extract_epi64::<2>(sum),
            _mm256_extract_epi64::<3>(sum),
        ]
        .into_iter()
        .fold(0u64, |n, x| n.wrapping_add(x.cast_unsigned()))
    }))
}

#[target_feature(enable = "avx2")]
pub(super) fn absorb(acc: &[[u8; 8]; 5], raw: &[u8; 16], blocks: &[[u8; 64]]) -> [[u8; 8]; 5] {
    let mut h = acc.map(|v| u64::from_le_bytes(v) & MASK);
    let r = limbs(u128::from_le_bytes(*raw) & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff);
    let mut powers = Scratch([[[0; 8]; 5]; 4]);
    let [r4, r3, r2, r1] = &mut powers.0;
    *r1 = r.map(u64::to_le_bytes);
    *r2 = product(r, r).map(u64::to_le_bytes);
    *r3 = product(r2.map(u64::from_le_bytes), r).map(u64::to_le_bytes);
    *r4 = product(r2.map(u64::from_le_bytes), r2.map(u64::from_le_bytes)).map(u64::to_le_bytes);
    let mut storage = [[_mm256_setzero_si256(); 5]; 5];
    let table = ClearingTable(&mut storage);
    // Output column j uses multiplier limb (j-i) mod 5 for input limb i,
    // multiplied by five if it wraps. Fill the table before the group loop.
    let [ra, sa, ta, ua, va] = r4;
    let [rb, sb, tb, ub, vb] = r3;
    let [rc, sc, tc, uc, vc] = r2;
    let [rd, sd, td, ud, vd] = r1;
    let r = pack([*ra, *rb, *rc, *rd]);
    let s = pack([*sa, *sb, *sc, *sd]);
    let t = pack([*ta, *tb, *tc, *td]);
    let u = pack([*ua, *ub, *uc, *ud]);
    let v = pack([*va, *vb, *vc, *vd]);
    let [s5, t5, u5, v5] = [s, t, u, v].map(|x| _mm256_add_epi64(x, _mm256_slli_epi64::<2>(x)));
    *table.0 = [
        [r, v5, u5, t5, s5],
        [s, r, v5, u5, t5],
        [t, s, r, v5, u5],
        [u, t, s, r, v5],
        [v, u, t, s, r],
    ];
    drop(powers);
    for block in blocks {
        h = group(h, block, table.0);
    }
    h.map(u64::to_le_bytes)
}

#[cfg(test)]
#[test]
fn packed_table_clears_its_live_storage() {
    #[target_feature(enable = "avx2")]
    fn exercise(unwind: bool) {
        let mut storage = [[_mm256_set1_epi64x(-1); 5]; 5];
        let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = ClearingTable(&mut storage);
            if unwind {
                std::panic::resume_unwind(std::boxed::Box::new(()));
            }
        }));
        assert_eq!(outcome.is_err(), unwind);
        for v in storage.into_iter().flatten() {
            assert_ne!(_mm256_testz_si256(v, v), 0);
        }
    }
    if std::is_x86_feature_detected!("avx2") {
        for unwind in [false, true] {
            // SAFETY: test only, after detecting usable AVX2 on the host.
            unsafe { exercise(unwind) };
        }
    }
}
