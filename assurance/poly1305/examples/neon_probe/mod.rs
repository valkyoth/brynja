//! Two adjacent blocks of one public fixture; no production secret ownership.
use core::arch::aarch64::*;

type Limbs = [u32; 5];
type Weights = [[uint32x2_t; 5]; 5];
const MASK: u64 = (1 << 26) - 1;

fn limbs(n: u128) -> Limbs {
    core::array::from_fn(|i| ((n >> (26 * i)) as u32) & MASK as u32)
}

fn message(bytes: &[u8]) -> Limbs {
    let mut buf = [0; 16];
    buf[..bytes.len()].copy_from_slice(bytes);
    let mut m = limbs(u128::from_le_bytes(buf));
    let bit = 8 * bytes.len();
    m[bit / 26] |= 1 << (bit % 26);
    m
}

fn add(a: Limbs, b: Limbs) -> Limbs {
    core::array::from_fn(|i| a[i] + b[i])
}

fn reduce(mut cols: [u64; 5]) -> Limbs {
    for _ in 0..3 {
        let mut carry = 0;
        for x in &mut cols {
            let n = *x + carry;
            *x = n & MASK;
            carry = n >> 26;
        }
        cols[0] += 5 * carry;
    }
    debug_assert!(cols.iter().all(|&x| x <= MASK));
    cols.map(|x| x as u32)
}

fn factor(r: Limbs, col: usize, i: usize) -> u32 {
    r[(col + 5 - i) % 5] * if i > col { 5 } else { 1 }
}

fn mul(a: Limbs, r: Limbs) -> Limbs {
    reduce(core::array::from_fn(|col| {
        (0..5)
            .map(|i| u64::from(a[i]) * u64::from(factor(r, col, i)))
            .sum()
    }))
}

#[target_feature(enable = "neon")]
fn pair(a: u32, b: u32) -> uint32x2_t {
    vset_lane_u32::<1>(b, vdup_n_u32(a))
}

// (h + m0) * r² + m1 * r, not two independent messages. With B=2^26,
// inputs are <2B and <B, weights <5B; each horizontal sum <75B² <2^59.
#[inline(never)]
#[target_feature(enable = "neon")]
fn two_blocks(h: Limbs, bytes: &[u8; 32], weights: &Weights) -> Limbs {
    let (first, second) = bytes.split_at(16);
    let lo = add(h, message(first));
    let hi = message(second);
    let words: [_; 5] = core::array::from_fn(|i| pair(lo[i], hi[i]));
    reduce(weights.map(|w| {
        let mut total = vmull_u32(words[0], w[0]);
        for i in 1..5 {
            total = vmlal_u32(total, words[i], w[i]);
        }
        vaddvq_u64(total)
    }))
}

#[target_feature(enable = "neon")]
pub(super) fn tag(key: &[u8; 32], data: &[u8]) -> [u8; 16] {
    let raw = u128::from_le_bytes(key[..16].try_into().unwrap());
    let r = limbs(raw & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff);
    let (pairs, tail) = data.as_chunks::<32>();
    let mut h = [0; 5];
    if !pairs.is_empty() {
        let r2 = mul(r, r);
        let weights = core::array::from_fn(|col| {
            core::array::from_fn(|i| pair(factor(r2, col, i), factor(r, col, i)))
        });
        for bytes in pairs {
            h = two_blocks(h, bytes, &weights);
        }
    }
    for bytes in tail.chunks(16) {
        h = mul(add(h, message(bytes)), r);
    }
    let carry = h.iter().fold(5, |c, x| (c + x) >> 26);
    let low = h
        .iter()
        .rev()
        .fold(0u128, |n, &x| (n << 26) | u128::from(x));
    low.wrapping_add(u128::from(5 * carry))
        .wrapping_add(u128::from_le_bytes(key[16..].try_into().unwrap()))
        .to_le_bytes()
}
