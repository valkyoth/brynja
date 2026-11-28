//! Public inputs only; no production ownership or erasure guarantees.
use core::arch::global_asm;
global_asm!(include_str!("columns.S"), options(raw));

type Limbs = [u32; 5];
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

fn reduce(mut col: [u64; 5]) -> Limbs {
    for _ in 0..3 {
        let mut carry = 0;
        for x in &mut col {
            let n = *x + carry;
            *x = n & MASK;
            carry = n >> 26;
        }
        col[0] += 5 * carry;
    }
    debug_assert!(col.iter().all(|&x| x <= MASK));
    col.map(|x| x as u32)
}

fn mul(a: Limbs, b: Limbs) -> Limbs {
    reduce(core::array::from_fn(|j| {
        (0..5)
            .map(|i| u64::from(a[i]) * u64::from(b[(j + 5 - i) % 5]) * if i > j { 5 } else { 1 })
            .sum()
    }))
}

pub(super) struct Vector(());

impl Vector {
    pub(super) fn detect() -> Option<Self> {
        unsafe extern "C" {
            fn getauxval(kind: core::ffi::c_ulong) -> core::ffi::c_ulong;
        }
        // SAFETY: numeric AT_HWCAP selector only. A missing value refuses V.
        let caps = unsafe { getauxval(16) };
        (caps & (1 << (b'V' - b'A')) != 0).then_some(Self(()))
    }

    pub(super) fn tag(&self, key: &[u8; 32], data: &[u8]) -> [u8; 16] {
        let r = limbs(
            u128::from_le_bytes(key[..16].try_into().unwrap())
                & 0x0fff_fffc_0fff_fffc_0fff_fffc_0fff_ffff,
        );
        let (groups, tail) = data.as_chunks::<64>();
        let mut h = [0; 5];
        if !groups.is_empty() {
            let r2 = mul(r, r);
            let powers = [mul(r2, r2), mul(r2, r), r2, r];
            let weights: [[u32; 4]; 9] =
                core::array::from_fn(|i| powers.map(|p| if i < 5 { p[i] } else { 5 * p[i - 4] }));
            for bytes in groups {
                let blocks = bytes.as_chunks::<16>().0;
                let mut m = core::array::from_fn::<_, 4, _>(|i| message(&blocks[i]));
                m[0] = add(m[0], h);
                let words: [[u32; 4]; 5] = core::array::from_fn(|i| m.map(|x| x[i]));
                let mut sum = [0u64; 5];
                unsafe extern "C" {
                    fn brynja_probe_poly1305_rvv_columns(
                        words: *const [[u32; 4]; 5],
                        weights: *const [[u32; 4]; 9],
                        sum: *mut [u64; 5],
                    );
                }
                // SAFETY: private proof of Linux-advertised V; full V supports
                // VL=4 at e32,m1 and e64,m2. Each load fits its aligned row;
                // the five u64 stores target only the exclusive sum array.
                unsafe { brynja_probe_poly1305_rvv_columns(&words, &weights, &mut sum) };
                // Even the first lane has limbs <2B, all factors <5B (B=2^26).
                // Four five-term lanes sum to <200 B², hence no u64 wrap.
                h = reduce(sum);
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
}
