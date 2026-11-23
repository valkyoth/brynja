//! Direct arithmetic and public incremental GHASH regressions.
#![forbid(unsafe_code)]

#[path = "../src/ghash/field.rs"]
mod field;
#[path = "ghash_vectors/nist.rs"]
mod nist;
#[cfg(brynja_ghash_pclmul_evidence)]
#[path = "ghash_field/accelerated.rs"]
mod pclmul;
#[cfg(brynja_ghash_pmull_evidence)]
#[path = "ghash_field/accelerated.rs"]
mod pmull;
#[cfg(brynja_ghash_rv64_evidence)]
#[path = "ghash_field/accelerated.rs"]
mod rv64;
#[cfg(all(
    any(
        brynja_ghash_pclmul_evidence,
        brynja_ghash_pmull_evidence,
        brynja_ghash_rv64_evidence
    ),
    feature = "hazmat-aes-block"
))]
#[path = "ghash_field/scalar_aes.rs"]
mod scalar_aes;
use brynja_crypto::ghash::{Error, Ghash};

#[test]
fn wire_order_and_reduction_boundary() {
    let one = 1u128 << 127;
    for i in 0..128 {
        let basis = 1 << i;
        assert_eq!(field::multiply(one, basis), basis);
        assert_eq!(field::multiply(basis, one), basis);
        assert_eq!(field::multiply(basis, 0), 0);
    }
    assert_eq!(field::multiply(1, one >> 1), 0xe1 << 120);
}

#[test]
fn zero_subkey_preserves_exact_field_semantics() -> Result<(), Error> {
    let (mut work, mut out) = ([0xa5; 16], [0x5a; 16]);
    let mut hash = Ghash::new(&[0; 16], &mut work, 32);
    hash.update(&[0x63; 17])?;
    hash.update(&[0xe1; 15])?;
    assert_eq!(hash.finish(&mut out)?.expose(), [0; 16]);
    Ok(())
}

#[test]
fn nist_gcm_aes128_example_2_ghash_before_tag_mask() {
    // NIST AES_GCM.pdf, AES-128 Example #2: four ciphertext blocks, no AAD.
    // The final block encodes the two bit lengths; it is supplied by GCM,
    // not added implicitly by the GHASH primitive.
    let h = 0xb83b533708bf535d0aa6e52980d53b78;
    let blocks = [
        0x42831ec2217774244b7221b784d0d49c,
        0xe3aa212f2c02a4e035c17e2329aca12e,
        0x21d514b25466931c7d8f6a5aac84aa05,
        0x1ba30b396a0aac973d58e091473f5985,
        512,
    ];
    let s = blocks.into_iter().fold(0, |y, x| field::multiply(y ^ x, h));
    assert_eq!(s, 0x7f1b32b81b820d02614f8895ac1d4eac);
}

#[test]
fn every_nist_split_including_empty_updates() -> Result<(), Error> {
    let h = 0xb83b533708bf535d0aa6e52980d53b78u128.to_be_bytes();
    let input: Vec<_> = [
        0x42831ec2217774244b7221b784d0d49cu128,
        0xe3aa212f2c02a4e035c17e2329aca12e,
        0x21d514b25466931c7d8f6a5aac84aa05,
        0x1ba30b396a0aac973d58e091473f5985,
        512,
    ]
    .into_iter()
    .flat_map(u128::to_be_bytes)
    .collect();
    let expected = 0x7f1b32b81b820d02614f8895ac1d4eacu128.to_be_bytes();
    for split in 0..=input.len() {
        let (left, right) = input.split_at(split);
        let mut work = [0xa5; 16];
        let mut output = [0x5a; 16];
        let mut g = Ghash::new(&h, &mut work, 80);
        g.update(left)?;
        g.update(&[])?;
        for b in right {
            g.update(core::slice::from_ref(b))?;
        }
        let result = g.finish(&mut output)?;
        assert_eq!(result.expose(), expected);
        assert_eq!(work, [0; 16]);
        result.clear();
        assert_eq!(output, [0; 16]);
    }
    Ok(())
}

#[test]
fn budget_failure_is_atomic_and_empty_is_zero() -> Result<(), Error> {
    let one = (1u128 << 127).to_be_bytes();
    let mut work = [0xff; 16];
    let mut output = [0xff; 16];
    let mut g = Ghash::new(&one, &mut work, 16);
    g.update(&[0xa5; 7])?;
    assert_eq!(g.update(&[0; 10]), Err(Error::LimitExceeded));
    g.update(&[0xa5; 9])?;
    assert_eq!(g.update(&[0]), Err(Error::LimitExceeded));
    assert_eq!(g.finish(&mut output)?.expose(), [0xa5; 16]);
    assert_eq!(output, [0; 16]); // temporary result was dropped
    let mut empty = Ghash::new(&one, &mut work, 0);
    empty.update(&[])?;
    assert_eq!(empty.finish(&mut output)?.expose(), [0; 16]);
    Ok(())
}

#[test]
fn partial_finish_and_cancellation_clear_workspace() -> Result<(), Error> {
    for tail in 1..16 {
        let mut work = [0x5a; 16];
        let mut output = [0xa5; 16];
        let mut g = Ghash::new(&[0x17; 16], &mut work, u64::MAX);
        g.update(&[0x68; 16])?;
        g.update(&vec![0x49; tail])?;
        assert!(matches!(g.finish(&mut output), Err(Error::PartialBlock)));
        assert_eq!(work, [0; 16]);
        assert_eq!(output, [0xa5; 16]);
        let mut cancelled = Ghash::new(&[0x18; 16], &mut work, 16);
        cancelled.update(&[0x93])?;
        drop(cancelled);
        assert_eq!(work, [0; 16]);
    }
    Ok(())
}

// Test oracle for public vectors only. Multiply the coefficient polynomials
// first, then divide the full product by x^128 + x^7 + x^2 + x + 1.
// Unlike the portable implementation this never uses a shift/reduce round.
fn polynomial_product(a: u128, b: u128) -> u128 {
    let mut product = vec![false; 255];
    for i in 0..128 {
        if (a.reverse_bits() >> i) & 1 == 1 {
            for (j, term) in product.iter_mut().skip(i).take(128).enumerate() {
                *term ^= (b.reverse_bits() >> j) & 1 == 1;
            }
        }
    }
    while product.len() > 128 {
        if product.pop() == Some(true) {
            let degree = product.len().saturating_sub(128);
            for (d, term) in product.iter_mut().skip(degree).take(8).enumerate() {
                *term ^= matches!(d, 0 | 1 | 2 | 7);
            }
        }
    }
    product
        .into_iter()
        .fold(0, |acc, bit| (acc << 1) | u128::from(bit))
}

#[test]
fn differential_against_polynomial_long_division() {
    let mut seed = 0xe1b42f191607dd32aac46e751e47bc87u128;
    let mut sample = || {
        seed ^= seed << 23;
        seed ^= seed >> 17;
        seed ^= seed << 26;
        seed
    };
    for _ in 0..256 {
        let (a, b) = (sample(), sample());
        assert_eq!(field::multiply(a, b), polynomial_product(a, b));
    }
}
