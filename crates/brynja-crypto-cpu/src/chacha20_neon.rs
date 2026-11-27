//! Each NEON lane is a separate IETF block; no cross-lane shuffle in a round.
#![allow(unsafe_code)]
type Column = [[u8; 4]; 4];
use core::arch::aarch64::*;

fn vector(c: Column) -> uint32x4_t {
    // SAFETY: both are 16 bytes of integers, all bit patterns valid. By value:
    // no aligned pointer or reference is constructed from the byte array.
    unsafe { core::mem::transmute(c) }
}

fn column(v: uint32x4_t) -> Column {
    // SAFETY: exact inverse of vector on this little-endian AArch64 target.
    unsafe { core::mem::transmute(v) }
}

/// Apply ten ChaCha column/diagonal double rounds in place, without feedforward.
/// Each of the four little-endian lanes is a separate state. This low-level
/// permutation does not reserve counters or provide a complete stream cipher.
pub fn rounds(state: &mut [[[u8; 4]; 4]; 16]) {
    // SAFETY: the module is compiled only for little-endian AArch64 targets with NEON enabled.
    unsafe { packed_rounds(state) }
}

#[inline(never)]
#[target_feature(enable = "neon")]
fn packed_rounds(state: &mut [Column; 16]) {
    macro_rules! rol {
        ($x:expr, $left:literal, $right:literal) => {{
            let t = $x;
            vsriq_n_u32::<$right>(vshlq_n_u32::<$left>(t), t)
        }};
    }
    macro_rules! quarter {
        ($a:ident,$b:ident,$c:ident,$d:ident) => {{
            $a = vaddq_u32($a, $b);
            $d = rol!(veorq_u32($d, $a), 16, 16);
            $c = vaddq_u32($c, $d);
            $b = rol!(veorq_u32($b, $c), 12, 20);
            $a = vaddq_u32($a, $b);
            $d = rol!(veorq_u32($d, $a), 8, 24);
            $c = vaddq_u32($c, $d);
            $b = rol!(veorq_u32($b, $c), 7, 25);
        }};
    }
    let [
        mut a,
        mut b,
        mut c,
        mut d,
        mut e,
        mut f,
        mut g,
        mut h,
        mut i,
        mut j,
        mut k,
        mut l,
        mut m,
        mut n,
        mut o,
        mut p,
    ] = state.map(vector);
    for _ in 0..10 {
        quarter!(a, e, i, m);
        quarter!(b, f, j, n);
        quarter!(c, g, k, o);
        quarter!(d, h, l, p);
        quarter!(a, f, k, p);
        quarter!(b, g, l, m);
        quarter!(c, h, i, n);
        quarter!(d, e, j, o);
    }
    *state = [a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p].map(column);
}
