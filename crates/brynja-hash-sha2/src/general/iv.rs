use super::Sha512TBits;
use crate::compress64::compress;

const INITIAL: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

pub(super) fn label(parameter: Sha512TBits) -> ([u8; 11], usize) {
    let mut output = [0_u8; 11];
    output[..8].copy_from_slice(b"SHA-512/");
    let bits = parameter.bits();
    // Validated t is 1..=511. Each quotient/remainder here is one decimal
    // digit; casting cannot truncate. No locale, leading zero or terminator.
    let digits = [bits / 100, (bits / 10) % 10, bits % 10];
    let skip = if bits >= 100 {
        0
    } else if bits >= 10 {
        1
    } else {
        2
    };
    for (slot, digit) in output.iter_mut().skip(8).zip(digits.iter().skip(skip)) {
        *slot = b'0'.saturating_add(digit.to_le_bytes()[0]);
    }
    (output, 11_usize.saturating_sub(skip))
}

pub(super) fn derive(parameter: Sha512TBits) -> [u64; 8] {
    let (label, length) = label(parameter);
    let mut block = [0_u8; 128];
    for (slot, byte) in block.iter_mut().zip(label).take(length) {
        *slot = byte;
    }
    // Label length is 9..=11, so these fixed-block accesses are always valid.
    if let Some(marker) = block.get_mut(length) {
        *marker = 0x80;
    }
    block[112..].copy_from_slice(&((length as u128) * 8).to_be_bytes());
    let mut state = INITIAL;
    for word in &mut state {
        *word ^= 0xa5a5_a5a5_a5a5_a5a5;
    }
    compress(&mut state, &block);
    state
}
