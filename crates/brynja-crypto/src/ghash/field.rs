//! GHASH field arithmetic, NIST SP 800-38D §6.3, Algorithm 1.
//! In this bit ordering the most significant bit represents the constant 1.

// No table lookups or input-dependent branches in source. This is not an
// emitted-code or timing qualification.
pub(super) fn multiply(mut x: u128, mut v: u128) -> u128 {
    const REDUCTION: u128 = 0xe1 << 120;
    let mut z = 0;
    for _ in 0..128 {
        z ^= v & 0u128.wrapping_sub(x >> 127);
        let reduction = REDUCTION & 0u128.wrapping_sub(v & 1);
        v = (v >> 1) ^ reduction;
        x <<= 1;
    }
    z
}
