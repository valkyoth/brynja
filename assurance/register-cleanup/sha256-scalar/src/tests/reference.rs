// Independently constructed prime/cube-root table and high-level round model.
pub(super) fn constants() -> [u32; 64] {
    let mut result = [0; 64];
    let mut count = 0;
    for candidate in 2_u32..=311 {
        if (2..candidate).any(|d| candidate % d == 0) {
            continue;
        }
        let root = f64::from(candidate).cbrt();
        result[count] = ((root - root.floor()) * 4294967296.0) as u32;
        count += 1;
    }
    assert_eq!(count, 64);
    result
}

pub(super) fn compress(mut state: [u8; 64], block: &[u8; 128]) -> [u8; 64] {
    let mut initial = [0_u32; 8];
    for (word, bytes) in initial.iter_mut().zip(state.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    let mut words = [0_u32; 64];
    for (word, bytes) in words[..16].iter_mut().zip(block.as_chunks::<4>().0) {
        *word = u32::from_be_bytes(*bytes);
    }
    for i in 16..64 {
        let x = words[i - 15];
        let y = words[i - 2];
        let s0 = x.rotate_right(7) ^ x.rotate_right(18) ^ (x >> 3);
        let s1 = y.rotate_right(17) ^ y.rotate_right(19) ^ (y >> 10);
        words[i] = words[i - 16]
            .wrapping_add(s0)
            .wrapping_add(words[i - 7])
            .wrapping_add(s1);
    }
    let mut work = initial;
    for (word, k) in words.into_iter().zip(constants()) {
        let [a, b, c, d, e, f, g, h] = work;
        let choice = (e & f) ^ (!e & g);
        let majority = (a & b) ^ (a & c) ^ (b & c);
        let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(choice)
            .wrapping_add(k)
            .wrapping_add(word);
        let t2 = s0.wrapping_add(majority);
        work = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
    }
    for ((bytes, old), new) in state
        .as_chunks_mut::<4>()
        .0
        .iter_mut()
        .zip(initial)
        .zip(work)
    {
        *bytes = old.wrapping_add(new).to_be_bytes();
    }
    state
}

#[test]
fn published_abc() {
    let iv = [
        0x6a09e667_u32,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19,
    ];
    let mut state = [0xa5; 64];
    for (bytes, value) in state.as_chunks_mut::<4>().0.iter_mut().zip(iv) {
        *bytes = value.to_be_bytes();
    }
    let mut block = [0; 128];
    block[..4].copy_from_slice(b"abc\x80");
    block[63] = 24;
    let result = compress(state, &block);
    assert_eq!(
        &result[..32],
        &[
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
            0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
            0xf2, 0x00, 0x15, 0xad
        ]
    );
    assert_eq!(&result[32..], &[0xa5; 32]);
}
