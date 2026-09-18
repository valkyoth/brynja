// Independent array/rotate model; no production constants, source or schedule.
pub(super) fn compress(state: [u8; 20], block: &[u8; 64]) -> [u8; 20] {
    let mut initial = [0_u32; 5];
    for (word, bytes) in initial.iter_mut().zip(state.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    let mut words = [0_u32; 80];
    for (word, bytes) in words.iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    for i in 16..80 {
        words[i] = (words[i - 16] ^ words[i - 14] ^ words[i - 8] ^ words[i - 3]).rotate_left(1);
    }
    let mut work = initial;
    for (round, message) in words.into_iter().enumerate() {
        let [a, b, c, d, e] = work;
        let f = match round / 20 {
            0 => (b & c) | (!b & d),
            2 => (b & c) | (b & d) | (c & d),
            _ => b ^ c ^ d,
        };
        let k = [0x5a82_7999, 0x6ed9_eba1, 0x8f1b_bcdc, 0xca62_c1d6][round / 20];
        work = [
            a.rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(message),
            a,
            b.rotate_right(2),
            c,
            d,
        ];
    }
    let mut result = [0_u8; 20];
    for ((out, old), new) in result
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(initial)
        .zip(work)
    {
        *out = old.wrapping_add(new).to_be_bytes();
    }
    result
}

#[test]
fn published_abc() {
    let iv = [
        0x67, 0x45, 0x23, 0x01, 0xef, 0xcd, 0xab, 0x89, 0x98, 0xba, 0xdc, 0xfe, 0x10, 0x32, 0x54,
        0x76, 0xc3, 0xd2, 0xe1, 0xf0,
    ];
    let mut block = [0; 64];
    block[..4].copy_from_slice(b"abc\x80");
    block[63] = 24;
    assert_eq!(
        compress(iv, &block),
        [
            0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
            0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d
        ]
    );
}
