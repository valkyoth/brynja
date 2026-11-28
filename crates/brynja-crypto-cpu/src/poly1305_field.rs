//! Shared radix-2^26 arithmetic for the opt-in SIMD bridges.
use brynja_core::clear_owned_region;

pub(super) type F = [u64; 5];
const MASK: u64 = (1 << 26) - 1;

pub(super) fn limbs(mut n: u128) -> F {
    core::array::from_fn(|_| {
        let [a, b, c, d, ..] = n.to_le_bytes();
        n >>= 26;
        u64::from(u32::from_le_bytes([a, b, c, d])) & MASK
    })
}

pub(super) fn reduce(mut x: F) -> F {
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

pub(super) fn product(a: F, [r, s, t, u, v]: F) -> F {
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

pub(super) struct Scratch<const N: usize, const M: usize>(pub(super) [[[u8; 8]; M]; N]);
impl<const N: usize, const M: usize> Drop for Scratch<N, M> {
    fn drop(&mut self) {
        let _ = clear_owned_region(self.0.as_flattened_mut().as_flattened_mut());
    }
}

// Split before carrying: even a u64::MAX coefficient plus the preceding
// carry must not overflow. At the top limb, 2^130 is congruent to five.
pub(super) fn accumulator(raw: &[[u8; 8]; 5]) -> F {
    let [a, b, c, d, e] = raw.map(u64::from_le_bytes);
    reduce([
        (a & MASK).wrapping_add((e >> 26).wrapping_mul(5)),
        (b & MASK).wrapping_add(a >> 26),
        (c & MASK).wrapping_add(b >> 26),
        (d & MASK).wrapping_add(c >> 26),
        (e & MASK).wrapping_add(d >> 26),
    ])
}

#[cfg(test)]
#[test]
fn oversized_coefficients_are_carried_not_discarded() {
    for (i, expected) in [
        [0, 1, 0, 0, 0],
        [0, 0, 1, 0, 0],
        [0, 0, 0, 1, 0],
        [0, 0, 0, 0, 1],
        [5, 0, 0, 0, 0],
    ]
    .into_iter()
    .enumerate()
    {
        let h = core::array::from_fn(|j| (if i == j { 1u64 << 26 } else { 0 }).to_le_bytes());
        assert_eq!(accumulator(&h), expected);
    }
    assert_eq!(
        accumulator(&[u64::MAX.to_le_bytes(); 5]),
        [20479, 20479, 4095, 4095, 4095]
    );
}

#[cfg(kani)]
#[kani::proof]
#[kani::unwind(8)]
fn simd_packing_and_column_bounds() {
    let x = (kani::any::<u64>() & MASK) + (kani::any::<u64>() & MASK);
    let w = 5 * (kani::any::<u64>() & MASK);
    assert!(x <= u64::from(u32::MAX) && w <= u64::from(u32::MAX));
    // By monotonicity: five nonnegative products per column, at most four lanes.
    const COLUMN_MAX: u64 = (2 * MASK) * (5 * MASK) * 5 * 4;
    assert!(COLUMN_MAX < (1 << 60));
    let cols: F = kani::any();
    let cols = cols.map(|n| n & ((1 << 60) - 1));
    assert!(reduce(cols).iter().all(|n| *n <= MASK));
}
