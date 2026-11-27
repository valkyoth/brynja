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

#[cfg(test)]
mod tests {
    use super::multiply;

    #[test]
    fn nist_first_product() {
        // Zero AES-128 key, one ciphertext block, before the length block.
        assert_eq!(
            multiply(
                0x0388dace60b6a392f328c2b971b2fe78,
                0x66e94bd4ef8a2c3b884cfa59ca342b2e
            ),
            0x5e2ec746917062882c85b0685353deb7
        );
    }

    #[test]
    fn nist_multiblock_recurrence() {
        // NIST AES_GCM.pdf, AES-128 Example #2: four ciphertext blocks,
        // then the encoded bit lengths. This example uses a different H.
        let h = 0xb83b533708bf535d0aa6e52980d53b78;
        let blocks = [
            0x42831ec2217774244b7221b784d0d49c,
            0xe3aa212f2c02a4e035c17e2329aca12e,
            0x21d514b25466931c7d8f6a5aac84aa05,
            0x1ba30b396a0aac973d58e091473f5985,
            512,
        ];
        assert_eq!(
            blocks.into_iter().fold(0, |y, x| multiply(y ^ x, h)),
            0x7f1b32b81b820d02614f8895ac1d4eac
        );
    }
}
