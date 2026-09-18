// Independently derived constants: floor(cuberoot(prime * 2^192)) modulo 2^64.
// Generated with integer binary search (no floating point or production table).
pub(super) const fn constants() -> [u64; 80] {
    [
        0x428a2f98d728ae22,
        0x7137449123ef65cd,
        0xb5c0fbcfec4d3b2f,
        0xe9b5dba58189dbbc,
        0x3956c25bf348b538,
        0x59f111f1b605d019,
        0x923f82a4af194f9b,
        0xab1c5ed5da6d8118,
        0xd807aa98a3030242,
        0x12835b0145706fbe,
        0x243185be4ee4b28c,
        0x550c7dc3d5ffb4e2,
        0x72be5d74f27b896f,
        0x80deb1fe3b1696b1,
        0x9bdc06a725c71235,
        0xc19bf174cf692694,
        0xe49b69c19ef14ad2,
        0xefbe4786384f25e3,
        0x0fc19dc68b8cd5b5,
        0x240ca1cc77ac9c65,
        0x2de92c6f592b0275,
        0x4a7484aa6ea6e483,
        0x5cb0a9dcbd41fbd4,
        0x76f988da831153b5,
        0x983e5152ee66dfab,
        0xa831c66d2db43210,
        0xb00327c898fb213f,
        0xbf597fc7beef0ee4,
        0xc6e00bf33da88fc2,
        0xd5a79147930aa725,
        0x06ca6351e003826f,
        0x142929670a0e6e70,
        0x27b70a8546d22ffc,
        0x2e1b21385c26c926,
        0x4d2c6dfc5ac42aed,
        0x53380d139d95b3df,
        0x650a73548baf63de,
        0x766a0abb3c77b2a8,
        0x81c2c92e47edaee6,
        0x92722c851482353b,
        0xa2bfe8a14cf10364,
        0xa81a664bbc423001,
        0xc24b8b70d0f89791,
        0xc76c51a30654be30,
        0xd192e819d6ef5218,
        0xd69906245565a910,
        0xf40e35855771202a,
        0x106aa07032bbd1b8,
        0x19a4c116b8d2d0c8,
        0x1e376c085141ab53,
        0x2748774cdf8eeb99,
        0x34b0bcb5e19b48a8,
        0x391c0cb3c5c95a63,
        0x4ed8aa4ae3418acb,
        0x5b9cca4f7763e373,
        0x682e6ff3d6b2b8a3,
        0x748f82ee5defb2fc,
        0x78a5636f43172f60,
        0x84c87814a1f0ab72,
        0x8cc702081a6439ec,
        0x90befffa23631e28,
        0xa4506cebde82bde9,
        0xbef9a3f7b2c67915,
        0xc67178f2e372532b,
        0xca273eceea26619c,
        0xd186b8c721c0c207,
        0xeada7dd6cde0eb1e,
        0xf57d4f7fee6ed178,
        0x06f067aa72176fba,
        0x0a637dc5a2c898a6,
        0x113f9804bef90dae,
        0x1b710b35131c471b,
        0x28db77f523047d84,
        0x32caab7b40c72493,
        0x3c9ebe0a15c9bebc,
        0x431d67c49c100d4c,
        0x4cc5d4becb3e42b6,
        0x597f299cfc657e2a,
        0x5fcb6fab3ad6faec,
        0x6c44198c4a475817,
    ]
}

pub(super) fn compress(mut state: [u8; 64], block: &[u8; 128]) -> [u8; 64] {
    let mut initial = [0_u64; 8];
    for (word, bytes) in initial.iter_mut().zip(state.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*bytes);
    }
    let mut words = [0_u64; 80];
    for (word, bytes) in words[..16].iter_mut().zip(block.as_chunks::<8>().0) {
        *word = u64::from_be_bytes(*bytes);
    }
    for i in 16..80 {
        let x = words[i - 15];
        let y = words[i - 2];
        let s0 = x.rotate_right(1) ^ x.rotate_right(8) ^ (x >> 7);
        let s1 = y.rotate_right(19) ^ y.rotate_right(61) ^ (y >> 6);
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
        let s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let t1 = h
            .wrapping_add(s1)
            .wrapping_add(choice)
            .wrapping_add(k)
            .wrapping_add(word);
        let t2 = s0.wrapping_add(majority);
        work = [t1.wrapping_add(t2), a, b, c, d.wrapping_add(t1), e, f, g];
    }
    for ((bytes, old), new) in state
        .as_chunks_mut::<8>()
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
        0x6a09e667f3bcc908_u64,
        0xbb67ae8584caa73b,
        0x3c6ef372fe94f82b,
        0xa54ff53a5f1d36f1,
        0x510e527fade682d1,
        0x9b05688c2b3e6c1f,
        0x1f83d9abfb41bd6b,
        0x5be0cd19137e2179,
    ];
    let mut state = [0; 64];
    for (bytes, word) in state.as_chunks_mut::<8>().0.iter_mut().zip(iv) {
        *bytes = word.to_be_bytes();
    }
    let mut block = [0; 128];
    block[..4].copy_from_slice(b"abc\x80");
    block[127] = 24;
    assert_eq!(
        compress(state, &block),
        [
            0xdd, 0xaf, 0x35, 0xa1, 0x93, 0x61, 0x7a, 0xba, 0xcc, 0x41, 0x73, 0x49, 0xae, 0x20,
            0x41, 0x31, 0x12, 0xe6, 0xfa, 0x4e, 0x89, 0xa9, 0x7e, 0xa2, 0x0a, 0x9e, 0xee, 0xe6,
            0x4b, 0x55, 0xd3, 0x9a, 0x21, 0x92, 0x99, 0x2a, 0x27, 0x4f, 0xc1, 0xa8, 0x36, 0xba,
            0x3c, 0x23, 0xa3, 0xfe, 0xeb, 0xbd, 0x45, 0x4d, 0x44, 0x23, 0x64, 0x3c, 0xe8, 0x0e,
            0x2a, 0x9a, 0xc9, 0x4f, 0xa5, 0x4c, 0xa4, 0x9f
        ]
    );
}
