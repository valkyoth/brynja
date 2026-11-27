//! Each XMM lane is a separate IETF block; no cross-lane shuffle in a round.
#![allow(unsafe_code)]
type Column = [[u8; 4]; 4];
use core::arch::x86_64::*;

fn vector(c: Column) -> __m128i {
    // SAFETY: both are 16 bytes of integers, all bit patterns valid. By value:
    // no aligned pointer or reference is constructed from the byte array.
    unsafe { core::mem::transmute(c) }
}

fn column(v: __m128i) -> Column {
    // SAFETY: exact inverse of vector on this little-endian x86-64 target.
    unsafe { core::mem::transmute(v) }
}

/// Apply ten ChaCha column/diagonal double rounds in place, without feedforward.
/// Each of the four little-endian lanes is a separate state. This low-level
/// permutation does not reserve counters or provide a complete stream cipher.
pub fn rounds(state: &mut [[[u8; 4]; 4]; 16]) {
    // SAFETY: the module is compiled only for x86-64 targets with SSE2 enabled.
    unsafe { packed_rounds(state) }
}

#[inline(never)]
#[target_feature(enable = "sse2")]
fn packed_rounds(state: &mut [Column; 16]) {
    macro_rules! rol {
        ($x:expr, $left:literal, $right:literal) => {{
            let t = $x;
            _mm_or_si128(_mm_slli_epi32::<$left>(t), _mm_srli_epi32::<$right>(t))
        }};
    }
    macro_rules! quarter {
        ($a:ident,$b:ident,$c:ident,$d:ident) => {{
            $a = _mm_add_epi32($a, $b);
            $d = rol!(_mm_xor_si128($d, $a), 16, 16);
            $c = _mm_add_epi32($c, $d);
            $b = rol!(_mm_xor_si128($b, $c), 12, 20);
            $a = _mm_add_epi32($a, $b);
            $d = rol!(_mm_xor_si128($d, $a), 8, 24);
            $c = _mm_add_epi32($c, $d);
            $b = rol!(_mm_xor_si128($b, $c), 7, 25);
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
