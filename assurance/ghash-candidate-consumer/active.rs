use brynja_crypto::ghash::{Error, Ghash};

#[test]
fn counts_completed_products_not_updates() -> Result<(), Error> {
    let key = (1_u128 << 127).to_be_bytes(); // GHASH identity in wire order
    let (mut work, mut out) = ([0xa5; 16], [0x5a; 16]);
    let mut g = Ghash::new(&key, &mut work, 32);
    for (data, expected) in [
        (&[0x41; 15][..], 0),
        (&[][..], 0),
        (&[0x41; 1][..], 1),
        (&[0x22; 16][..], 2),
    ] {
        g.update(data)?;
        assert_eq!(g.native_blocks()?, expected);
    }
    let result = g.finish(&mut out)?;
    assert_eq!(result.expose(), &[0x63; 16]);
    result.clear();
    assert_eq!((work, out), ([0; 16], [0; 16]));
    Ok(())
}
