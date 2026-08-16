#[cfg(test)]
use crate::compress64::compress;

#[cfg(test)]
const SHA512_INITIAL_STATE: [u64; 8] = [
    0x6a09_e667_f3bc_c908,
    0xbb67_ae85_84ca_a73b,
    0x3c6e_f372_fe94_f82b,
    0xa54f_f53a_5f1d_36f1,
    0x510e_527f_ade6_82d1,
    0x9b05_688c_2b3e_6c1f,
    0x1f83_d9ab_fb41_bd6b,
    0x5be0_cd19_137e_2179,
];

#[cfg(test)]
const IV_XOR_MASK: u64 = 0xa5a5_a5a5_a5a5_a5a5;

pub(crate) const SHA512_224_INITIAL_STATE: [u64; 8] = [
    0x8c3d_37c8_1954_4da2,
    0x73e1_9966_89dc_d4d6,
    0x1dfa_b7ae_32ff_9c82,
    0x679d_d514_582f_9fcf,
    0x0f6d_2b69_7bd4_4da8,
    0x77e3_6f73_04c4_8942,
    0x3f9d_85a8_6a1d_36c8,
    0x1112_e6ad_91d6_92a1,
];

pub(crate) const SHA512_256_INITIAL_STATE: [u64; 8] = [
    0x2231_2194_fc2b_f72c,
    0x9f55_5fa3_c84c_64c2,
    0x2393_b86b_6f53_b151,
    0x9638_7719_5940_eabd,
    0x9628_3ee2_a88e_ffe3,
    0xbe5e_1e25_5386_3992,
    0x2b01_99fc_2c85_b8aa,
    0x0eb7_2ddc_81c5_2ca2,
];

#[cfg(test)]
pub(crate) fn derive_sha512_224_initial_state() -> [u64; 8] {
    derive_initial_state(b"SHA-512/224")
}

#[cfg(test)]
pub(crate) fn derive_sha512_256_initial_state() -> [u64; 8] {
    derive_initial_state(b"SHA-512/256")
}

#[cfg(test)]
fn derive_initial_state(label: &[u8; 11]) -> [u64; 8] {
    let mut state = SHA512_INITIAL_STATE;
    for word in &mut state {
        *word ^= IV_XOR_MASK;
    }

    // Both approved identities are eleven-byte ASCII strings. Their complete
    // SHA-512 padding therefore occupies one block and encodes 88 message bits.
    let mut block = [0_u8; 128];
    for (target, byte) in block.iter_mut().zip(label.iter()) {
        *target = *byte;
    }
    if let Some(marker) = block.get_mut(label.len()) {
        *marker = 0x80;
    }
    let message_bits = (label.len() as u128).saturating_mul(8);
    for (target, byte) in block.iter_mut().skip(112).zip(message_bits.to_be_bytes()) {
        *target = byte;
    }
    compress(&mut state, &block);
    state
}

pub(crate) fn leftmost_bytes<const LENGTH: usize>(state: [u64; 8]) -> [u8; LENGTH] {
    let mut output = [0_u8; LENGTH];
    for (index, target) in output.iter_mut().enumerate() {
        let word = state.get(index / 8).copied().unwrap_or(0);
        *target = word.to_be_bytes().get(index % 8).copied().unwrap_or(0);
    }
    output
}

#[cfg(test)]
mod tests {
    use super::{
        SHA512_224_INITIAL_STATE, SHA512_256_INITIAL_STATE, derive_sha512_224_initial_state,
        derive_sha512_256_initial_state,
    };

    #[test]
    fn fips_sha512_t_derivation_matches_both_normative_initial_states() {
        assert_eq!(derive_sha512_224_initial_state(), SHA512_224_INITIAL_STATE);
        assert_eq!(derive_sha512_256_initial_state(), SHA512_256_INITIAL_STATE);
        assert_ne!(SHA512_224_INITIAL_STATE, SHA512_256_INITIAL_STATE);
    }
}
