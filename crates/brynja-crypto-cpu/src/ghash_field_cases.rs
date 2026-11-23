//! Common checkout-only field corpus. The wire-order oracle uses no candidate code.

// Independent serial oracle in wire order: no lane splitting, polynomial
// reflection, or wide-product reduction shared with the candidate.
fn reference(x: u128, mut h: u128) -> u128 {
    let mut z = 0;
    for bit in (0..128).rev() {
        if x & (1 << bit) != 0 {
            z ^= h;
        }
        let carry = h & 1;
        h >>= 1;
        if carry != 0 {
            h ^= 0xe1 << 120;
        }
    }
    z
}

pub(super) fn basis_and_dense<E>(
    mut product: impl FnMut(u128, u128) -> Result<u128, E>,
) -> Result<(), E> {
    for i in 0..128 {
        for j in 0..128 {
            let (x, h) = (1_u128 << i, 1_u128 << j);
            assert_eq!(product(x, h)?, reference(x, h), "bits {i}, {j}");
        }
    }
    for x in [0, 1, u128::MAX, 1 << 127] {
        for h in [0, 1, u128::MAX, 1 << 127] {
            assert_eq!(product(x, h)?, reference(x, h));
        }
    }
    fn next(mut s: u128) -> u128 {
        s ^= s << 23;
        s ^= s >> 17;
        s ^ (s << 26)
    }
    let mut s = 0x6a09e667f3bcc908bb67ae8584caa73b;
    for _ in 0..512 {
        let x = next(s);
        let h = next(x);
        s = next(h);
        let xh = product(x, h)?;
        let hs = product(h, s)?;
        assert_eq!(xh, reference(x, h));
        assert_eq!(product(xh, s)?, product(x, hs)?);
    }
    Ok(())
}

pub(super) fn framed<E>(mut product: impl FnMut(u128, u128) -> Result<u128, E>) -> Result<(), E> {
    // SP 800-38D GCM worked examples, AES-128 Encrypt-Generate example 2.
    // S is the published GHASH intermediate, not an authentication tag.
    let h = 0xb83b533708bf535d0aa6e52980d53b78;
    let blocks = [
        0x42831ec2217774244b7221b784d0d49c,
        0xe3aa212f2c02a4e035c17e2329aca12e,
        0x21d514b25466931c7d8f6a5aac84aa05,
        0x1ba30b396a0aac973d58e091473f5985,
        0x200,
    ];
    let s = blocks.into_iter().try_fold(0, |z, x| product(z ^ x, h))?;
    assert_eq!(s, 0x7f1b32b81b820d02614f8895ac1d4eac);
    Ok(())
}
