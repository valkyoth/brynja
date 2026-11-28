//! Radix B = 2^26, modulus B^5 - 5. All loops have public bounds.
const MASK: u64 = (1 << 26) - 1;

pub(super) fn load(bytes: &[u8]) -> u128 {
    bytes.iter().rev().fold(0, |n, b| (n << 8) | u128::from(*b))
}

fn limbs(mut n: u128) -> [u64; 5] {
    core::array::from_fn(|_| {
        let [a, b, c, d, ..] = n.to_le_bytes();
        n >>= 26;
        u64::from(u32::from_le_bytes([a, b, c, d])) & MASK
    })
}

fn carry(words: &mut [u64; 5]) -> u64 {
    let mut carry = 0;
    for x in words {
        let sum = x.wrapping_add(carry);
        *x = sum & MASK;
        carry = sum >> 26;
    }
    carry
}

pub(super) fn absorb(h: &mut [[u8; 8]; 5], raw_r: &[u8], block: &[u8; 16], full: bool) {
    let mut input = limbs(u128::from_le_bytes(*block));
    input[4] |= u64::from(full) << 24; // the appended 1 at bit 128
    for (term, limb) in input.iter_mut().zip(h.iter()) {
        *term = term.wrapping_add(u64::from_le_bytes(*limb));
    }
    let [a, b, c, d, e] = input;
    let [r, s, t, u, v] = limbs(load(raw_r) & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff);
    // Terms of degree >= 5 wrap with factor 5. Inputs are < 2B,
    // factors < 5B; each column sum fits in u64 (< 50 B^2).
    let dot = |factors: [u64; 5]| {
        [a, b, c, d, e]
            .into_iter()
            .zip(factors)
            .fold(0u64, |sum, (x, y)| sum.wrapping_add(x.wrapping_mul(y)))
    };
    let five = |x: u64| x.wrapping_mul(5);
    let mut product = [
        dot([r, five(v), five(u), five(t), five(s)]),
        dot([s, r, five(v), five(u), five(t)]),
        dot([t, s, r, five(v), five(u)]),
        dot([u, t, s, r, five(v)]),
        dot([v, u, t, s, r]),
    ];
    // After the first fold only limb 0 can exceed B. The next carry
    // out of limb 4 is at most one. If it occurs, limbs 1..4 have
    // just rolled over; folding that last 5 cannot overflow limb 4.
    for _ in 0..2 {
        let wrap = carry(&mut product);
        product[0] = product[0].wrapping_add(five(wrap));
    }
    let _ = carry(&mut product);
    *h = product.map(u64::to_le_bytes);
}

pub(super) fn finish(h: &[[u8; 8]; 5], pad: &[u8]) -> [u8; 16] {
    let words = h.map(u64::from_le_bytes);
    let mut plus_five = words;
    plus_five[0] = plus_five[0].wrapping_add(5);
    // For h < B^5, h >= p iff h+5 carries out. Only the low 128 bits
    // of (h mod p) + pad are needed. No secret-dependent selection.
    let quotient = carry(&mut plus_five);
    let low = words
        .iter()
        .rev()
        .fold(0u128, |acc, &w| (acc << 26) | u128::from(w));
    low.wrapping_add(u128::from(quotient.wrapping_mul(5)))
        .wrapping_add(load(pad))
        .to_le_bytes()
}
