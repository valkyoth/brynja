use crate::owner::Md5Owner;

// RFC 1321 §3.4. Constants and indices depend only on the public round.
// Working scalars retain the documented compiler-copy/register/spill limits.
const CONSTANTS: [u32; 64] = [
    0xd76a_a478,
    0xe8c7_b756,
    0x2420_70db,
    0xc1bd_ceee,
    0xf57c_0faf,
    0x4787_c62a,
    0xa830_4613,
    0xfd46_9501,
    0x6980_98d8,
    0x8b44_f7af,
    0xffff_5bb1,
    0x895c_d7be,
    0x6b90_1122,
    0xfd98_7193,
    0xa679_438e,
    0x49b4_0821,
    0xf61e_2562,
    0xc040_b340,
    0x265e_5a51,
    0xe9b6_c7aa,
    0xd62f_105d,
    0x0244_1453,
    0xd8a1_e681,
    0xe7d3_fbc8,
    0x21e1_cde6,
    0xc337_07d6,
    0xf4d5_0d87,
    0x455a_14ed,
    0xa9e3_e905,
    0xfcef_a3f8,
    0x676f_02d9,
    0x8d2a_4c8a,
    0xfffa_3942,
    0x8771_f681,
    0x6d9d_6122,
    0xfde5_380c,
    0xa4be_ea44,
    0x4bde_cfa9,
    0xf6bb_4b60,
    0xbebf_bc70,
    0x289b_7ec6,
    0xeaa1_27fa,
    0xd4ef_3085,
    0x0488_1d05,
    0xd9d4_d039,
    0xe6db_99e5,
    0x1fa2_7cf8,
    0xc4ac_5665,
    0xf429_2244,
    0x432a_ff97,
    0xab94_23a7,
    0xfc93_a039,
    0x655b_59c3,
    0x8f0c_cc92,
    0xffef_f47d,
    0x8584_5dd1,
    0x6fa8_7e4f,
    0xfe2c_e6e0,
    0xa301_4314,
    0x4e08_11a1,
    0xf753_7e82,
    0xbd3a_f235,
    0x2ad7_d2bb,
    0xeb86_d391,
];

pub(crate) fn compress(owner: &mut Md5Owner) {
    let mut a = read(&owner.chaining_state, 0);
    let mut b = read(&owner.chaining_state, 1);
    let mut c = read(&owner.chaining_state, 2);
    let mut d = read(&owner.chaining_state, 3);
    for (round, constant) in CONSTANTS.into_iter().enumerate() {
        let (function, index, shifts) = match round {
            0..=15 => ((b & c) | (!b & d), round, [7, 12, 17, 22]),
            16..=31 => (
                (b & d) | (c & !d),
                round.saturating_mul(5).saturating_add(1) % 16,
                [5, 9, 14, 20],
            ),
            32..=47 => (
                b ^ c ^ d,
                round.saturating_mul(3).saturating_add(5) % 16,
                [4, 11, 16, 23],
            ),
            _ => (c ^ (b | !d), round.saturating_mul(7) % 16, [6, 10, 15, 21]),
        };
        let shift = shifts.get(round % 4).copied().unwrap_or(0);
        let next = a
            .wrapping_add(function)
            .wrapping_add(read(&owner.block, index))
            .wrapping_add(constant)
            .rotate_left(shift)
            .wrapping_add(b);
        a = d;
        d = c;
        c = b;
        b = next;
    }
    add(&mut owner.chaining_state, 0, a);
    add(&mut owner.chaining_state, 1, b);
    add(&mut owner.chaining_state, 2, c);
    add(&mut owner.chaining_state, 3, d);
    owner.clear_block();
}

fn read(bytes: &[u8], index: usize) -> u32 {
    let mut word = 0_u32;
    for (byte, shift) in bytes
        .iter()
        .skip(index.saturating_mul(4))
        .take(4)
        .zip([0, 8, 16, 24])
    {
        word |= u32::from(*byte) << shift;
    }
    word
}

fn add(bytes: &mut [u8], index: usize, value: u32) {
    let value = read(bytes, index).wrapping_add(value);
    for (byte, shift) in bytes
        .iter_mut()
        .skip(index.saturating_mul(4))
        .take(4)
        .zip([0, 8, 16, 24])
    {
        // Masking proves conversion succeeds; the fallback is unreachable.
        *byte = u8::try_from((value >> shift) & 0xff).unwrap_or(0);
    }
}
