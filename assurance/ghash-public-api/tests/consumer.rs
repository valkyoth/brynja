use brynja_crypto::{framed, ghash::Error, ghash::Ghash};

// Test-only oracle for synthetic public inputs: form the entire polynomial
// product, then reduce high terms modulo x^128 + x^7 + x^2 + x + 1.
fn product(a: u128, b: u128) -> u128 {
    let (a, b) = (a.reverse_bits(), b.reverse_bits());
    let mut p = [0u8; 256];
    for i in 0..128 {
        for j in 0..128 {
            p[i + j] ^= ((a >> i) & (b >> j) & 1) as u8;
        }
    }
    for k in (128..255).rev() {
        for d in [0, 1, 2, 7] {
            p[k - 128 + d] ^= p[k];
        }
    }
    p[..128]
        .iter()
        .fold(0, |v, &bit| (v << 1) | u128::from(bit))
}

#[test]
fn multiblock_differential() -> Result<(), Error> {
    let mut seed = 1_u128;
    let mut next = || {
        seed ^= seed << 23;
        seed ^= seed >> 17;
        seed ^= seed << 26;
        seed
    };
    for _ in 0..64 {
        let h = next();
        let blocks = [next(), next(), next()];
        let expected = blocks
            .iter()
            .fold(0, |v, &x| product(v ^ x, h))
            .to_be_bytes();
        let bytes = blocks.map(u128::to_be_bytes);
        let (mut work, mut out) = ([0xff; 16], [0x55; 16]);
        let result = framed(&h.to_be_bytes(), &mut work, bytes.as_flattened(), &mut out)?;
        assert_eq!(result.expose(), expected);
        result.clear();
        assert_eq!((work, out), ([0; 16], [0; 16]));
    }
    Ok(())
}

#[test]
fn budget_rejection_preserves_state_at_every_block_offset() -> Result<(), Error> {
    let one = (1_u128 << 127).to_be_bytes();
    for prefix in 0..=16 {
        let (mut work, mut out) = ([0xff; 16], [0x55; 16]);
        let mut state = Ghash::new(&one, &mut work, 16);
        state.update(&[0x42; 16][..prefix])?;
        assert_eq!(
            state.update(&[0x99; 17][prefix..]),
            Err(Error::LimitExceeded)
        );
        state.update(&[])?;
        state.update(&[0x42; 16][prefix..])?;
        assert_eq!(state.finish(&mut out)?.expose(), &[0x42; 16]);
    }
    Ok(())
}

#[test]
fn empty_zero_subkey_and_unaligned_finalization() -> Result<(), Error> {
    let (mut work, mut out) = ([0xff; 16], [0x55; 16]);
    for len in 0..=32 {
        out.fill(0x55);
        let mut state = Ghash::new(&[0; 16], &mut work, u64::MAX);
        state.update(&[0xff; 32][..len])?;
        if len % 16 == 0 {
            assert_eq!(state.finish(&mut out)?.expose(), &[0; 16]);
        } else {
            assert!(matches!(state.finish(&mut out), Err(Error::PartialBlock)));
            assert_eq!(out, [0x55; 16]);
        }
        assert_eq!(work, [0; 16]);
    }
    Ok(())
}
