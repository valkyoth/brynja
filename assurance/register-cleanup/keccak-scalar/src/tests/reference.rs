pub(crate) const ZERO_STATE_RESULT: [u64; 25] = [
    0xf125_8f79_40e1_dde7,
    0x84d5_ccf9_33c0_478a,
    0xd598_261e_a65a_a9ee,
    0xbd15_4730_6f80_494d,
    0x8b28_4e05_6253_d057,
    0xff97_a42d_7f8e_6fd4,
    0x90fe_e5a0_a446_47c4,
    0x8c5b_da0c_d619_2e76,
    0xad30_a6f7_1b19_059c,
    0x3093_5ab7_d08f_fc64,
    0xeb5a_a93f_2317_d635,
    0xa9a6_e626_0d71_2103,
    0x81a5_7c16_dbcf_555f,
    0x43b8_31cd_0347_c826,
    0x01f2_2f1a_11a5_569f,
    0x05e5_635a_21d9_ae61,
    0x64be_fef2_8cc9_70f2,
    0x6136_7095_7bc4_6611,
    0xb87c_5a55_4fd0_0ecb,
    0x8c3e_e88a_1ccf_32c8,
    0x940c_7922_ae3a_2614,
    0x1841_f924_a2c5_09e4,
    0x16f5_3526_e704_65c2,
    0x75f6_44e9_7f30_a13b,
    0xeaf1_ff7b_5cec_a249,
];

// Independent coordinate recurrence and LFSR, not production lane tables.
pub(super) fn permute(bytes: &[u8]) -> [u8; 200] {
    let mut a = [0_u64; 25];
    for (word, part) in a.iter_mut().zip(bytes.as_chunks::<8>().0) {
        *word = u64::from_le_bytes(*part);
    }
    let mut lfsr = 1_u8;
    for _ in 0..24 {
        let mut c = [0; 5];
        for x in 0..5 {
            for y in 0..5 {
                c[x] ^= a[x + 5 * y];
            }
        }
        for x in 0..5 {
            let d = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
            for y in 0..5 {
                a[x + 5 * y] ^= d;
            }
        }
        let mut b = [0; 25];
        b[0] = a[0];
        let (mut x, mut y) = (1, 0);
        for t in 0..24_u32 {
            b[y + 5 * ((2 * x + 3 * y) % 5)] = a[x + 5 * y].rotate_left((t + 1) * (t + 2) / 2);
            (x, y) = (y, (2 * x + 3 * y) % 5);
        }
        for y in 0..5 {
            for x in 0..5 {
                a[x + 5 * y] = b[x + 5 * y] ^ ((!b[(x + 1) % 5 + 5 * y]) & b[(x + 2) % 5 + 5 * y]);
            }
        }
        let mut rc = 0;
        for j in 0..7 {
            if lfsr & 1 != 0 {
                rc ^= 1_u64 << ((1 << j) - 1);
            }
            lfsr = (lfsr << 1) ^ if lfsr & 0x80 != 0 { 0x71 } else { 0 };
        }
        a[0] ^= rc;
    }
    let mut result = [0; 200];
    for (part, word) in result.as_chunks_mut::<8>().0.iter_mut().zip(a) {
        *part = word.to_le_bytes();
    }
    result
}

#[test]
fn independent_oracle_known_answer() {
    let actual = permute(&[0; 200]);
    for (part, word) in actual.as_chunks::<8>().0.iter().zip(ZERO_STATE_RESULT) {
        assert_eq!(u64::from_le_bytes(*part), word);
    }
}
