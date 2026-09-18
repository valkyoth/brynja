//! Independent RFC 1321 equations and sine table, not the shipped compressor.
use super::{CONSTANTS, SHIFTS};

pub(super) fn compress(mut state: [u8; 16], block: &[u8; 64]) -> [u8; 16] {
    let initial =
        core::array::from_fn::<_, 4, _>(|i| u32::from_le_bytes(state.as_chunks::<4>().0[i]));
    let words =
        core::array::from_fn::<_, 16, _>(|i| u32::from_le_bytes(block.as_chunks::<4>().0[i]));
    let [mut a, mut b, mut c, mut d] = initial;
    for i in 0..64 {
        let (f, g, shift) = match i {
            0..=15 => ((b & c) | (!b & d), i, [7, 12, 17, 22][i % 4]),
            16..=31 => ((b & d) | (c & !d), (5 * i + 1) % 16, [5, 9, 14, 20][i % 4]),
            32..=47 => (b ^ c ^ d, (3 * i + 5) % 16, [4, 11, 16, 23][i % 4]),
            _ => (c ^ (b | !d), (7 * i) % 16, [6, 10, 15, 21][i % 4]),
        };
        let k = (((i + 1) as f64).sin().abs() * 4_294_967_296.0) as u32;
        let next = b.wrapping_add(
            a.wrapping_add(f)
                .wrapping_add(words[g])
                .wrapping_add(k)
                .rotate_left(shift),
        );
        (a, b, c, d) = (d, next, b, c);
    }
    for ((out, original), last) in state
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(initial)
        .zip([a, b, c, d])
    {
        *out = original.wrapping_add(last).to_le_bytes();
    }
    state
}

#[test]
fn rfc_abc_and_public_tables() {
    for (i, k) in CONSTANTS.iter().enumerate() {
        assert_eq!(*k, (((i + 1) as f64).sin().abs() * 4_294_967_296.0) as u32);
    }
    assert_eq!(
        SHIFTS,
        [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21]
    );
    let mut initial = [0; 16];
    for (bytes, word) in initial.as_chunks_mut::<4>().0.iter_mut().zip([
        0x67452301_u32,
        0xefcdab89,
        0x98badcfe,
        0x10325476,
    ]) {
        *bytes = word.to_le_bytes();
    }
    let mut block = [0; 64];
    block[..4].copy_from_slice(b"abc\x80");
    block[56] = 24;
    assert_eq!(
        compress(initial, &block),
        [
            0x90, 0x01, 0x50, 0x98, 0x3c, 0xd2, 0x4f, 0xb0, 0xd6, 0x96, 0x3f, 0x7d, 0x28, 0xe1,
            0x7f, 0x72
        ]
    );
}
