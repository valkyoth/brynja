use super::*;

#[test]
fn invalid_range_and_last_nonce() -> Result<(), Error> {
    let key = [0x31; 32];
    let new = |first, count| Sealer::from_reserved_range(&key, [0x87; 4], first, count);
    assert!(matches!(new(0, 0), Err(Error::Length)));
    assert!(matches!(new(u64::MAX, 2), Err(Error::Length)));
    let mut sender = new(u64::MAX - 1, 2)?;
    let mut dst = [0xaa];
    let mut scratch = [0xbb];
    assert_eq!(
        sender.seal(&[], &[], &mut dst, &mut scratch),
        Err(Error::Length)
    );
    assert_eq!((dst, scratch), ([0xaa], [0xbb]));
    assert_eq!(
        sender.seal_in_place(&[], &mut dst, &mut []),
        Err(Error::Length)
    );
    let (first, _) = sender.seal_in_place(&[], &mut [], &mut [])?;
    let (last, _) = sender.seal_in_place(&[], &mut [], &mut [])?;
    assert_eq!(
        first.split_at(4),
        (&[0x87; 4][..], &(u64::MAX - 1).to_be_bytes()[..])
    );
    assert_eq!(
        last.split_at(4),
        (&[0x87; 4][..], &u64::MAX.to_be_bytes()[..])
    );
    assert_eq!(
        sender.seal_in_place(&[], &mut dst, &mut scratch),
        Err(Error::Exhausted)
    );
    assert_eq!((dst, scratch), ([0xaa], [0xbb]));
    Ok(())
}

#[test]
fn empty_payload_and_tampered_inputs() -> Result<(), Error> {
    let key = [0x57; 32];
    let mut sender = Sealer::from_reserved_range(&key, [0x23; 4], 256, 2)?;
    let open = Opener::new(&key);
    let (iv, tag) = sender.seal(&[], &[], &mut [], &mut [])?;
    open.open(iv, &[], &tag, &[], &mut [], &mut [])?;
    assert_eq!(
        open.open(iv, &[1], &tag, &[], &mut [], &mut []),
        Err(Error::Authentication)
    );
    let mut data = [0xa5; 65];
    let mut work = [0x12; 65];
    let (iv, tag) = sender.seal_in_place(b"aad", &mut data, &mut work)?;
    let mut bad_iv = iv;
    let (first, _) = bad_iv.split_first_mut().ok_or(Error::Invariant)?;
    *first ^= 1;
    let mut bad_ct = data;
    let (last, _) = bad_ct.split_last_mut().ok_or(Error::Invariant)?;
    *last ^= 1;
    for (nonce, aad, mut ct) in [
        (bad_iv, b"aad", data),
        (iv, b"Aad", data),
        (iv, b"aad", bad_ct),
    ] {
        let before = ct;
        work.fill(0x7f);
        assert_eq!(
            open.open_in_place(nonce, aad, &tag, &mut ct, &mut work),
            Err(Error::Authentication)
        );
        assert_eq!(ct, before);
        assert_eq!(work, [0; 65]);
    }
    Ok(())
}

#[test]
fn failed_or_unwound_transaction_does_not_commit() {
    extern crate std;
    use std::panic::{AssertUnwindSafe, catch_unwind, resume_unwind};
    let mut dst = [0xa5; 8];
    let mut work = [0; 8];
    let result = Buffers::InPlace(&mut dst).transact(&mut work, |_, scratch| {
        scratch.fill(0x57);
        Err::<(), _>(Error::Invariant)
    });
    assert_eq!(result, Err(Error::Invariant));
    assert_eq!((dst, work), ([0xa5; 8], [0; 8]));
    let unwind = catch_unwind(AssertUnwindSafe(|| {
        Buffers::Separate(&[0; 8], &mut dst).transact(
            &mut work,
            |_, scratch| -> Result<(), Error> {
                scratch.fill(0x87);
                resume_unwind(std::boxed::Box::new(()))
            },
        )
    }));
    assert!(unwind.is_err());
    assert_eq!((dst, work), ([0xa5; 8], [0; 8]));
}
