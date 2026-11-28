use super::*;
use crate::execution::{AdmissionError, X86Pair};

fn probe() -> Result<Option<X86Pair>, Error> {
    match X86Pair::probe() {
        Ok(cpu) => Ok(Some(cpu)),
        Err(AdmissionError::Unavailable) => Ok(None),
        Err(_) => Err(Error::Invariant),
    }
}

#[test]
fn mixed_sender_burns_only_admitted_invocations() -> Result<(), Error> {
    let Some(mut pair) = probe()? else {
        return Ok(());
    };
    let key = [0xa3; 32];
    let mut sender = Sealer::from_reserved_range(&key, *b"pair", u64::MAX - 1, 2)?;
    let mut data = [0x64; 1];
    let mut wrong = [0x37; 2];
    assert_eq!(
        sender
            .with_pair(&mut pair)?
            .seal_in_place(&[], &mut data, &mut wrong),
        Err(Error::Length)
    );
    assert_eq!((data, wrong), ([0x64; 1], [0x37; 2]));
    let (first, _) = sender.seal_in_place(&[], &mut [], &mut [])?;
    let (last, _) = sender
        .with_pair(&mut pair)?
        .seal_in_place(&[], &mut [], &mut [])?;
    assert_eq!(first.split_at(4).1, (u64::MAX - 1).to_be_bytes());
    assert_eq!(last.split_at(4).1, u64::MAX.to_be_bytes());
    let mut work = [0x29; 1];
    assert_eq!(
        sender
            .with_pair(&mut pair)?
            .seal_in_place(&[], &mut data, &mut work),
        Err(Error::Exhausted)
    );
    assert_eq!((data, work), ([0x64; 1], [0x29; 1]));
    Ok(())
}

#[test]
fn bad_tag_stops_before_decryption_in_both_layouts() -> Result<(), Error> {
    let Some(mut cpu) = probe()? else {
        return Ok(());
    };
    let key = [0x63; 32];
    let aad = [0x59; 1031];
    let plain = [0x31; 1501];
    let mut ct = plain;
    let mut work = [0; 1501];
    let mut tx = Sealer::from_reserved_range(&key, *b"pair", 17, 1)?;
    let (nonce, tag) = tx
        .with_pair(&mut cpu)?
        .seal_in_place(&aad, &mut ct, &mut work)?;
    for in_place in [true, false] {
        let mut rx = Opener::new(&key).with_pair(&mut cpu)?;
        let mut bad = tag;
        bad[0] ^= 1;
        let before = if in_place { ct } else { [0x67; 1501] };
        let mut dst = before;
        work.fill(0x53);
        PLAN.set(Some((Stage::BeforePayload, false)));
        let result = if in_place {
            rx.open_in_place(nonce, &aad, &bad, &mut dst, &mut work)
        } else {
            rx.open(nonce, &aad, &bad, &ct, &mut dst, &mut work)
        };
        assert_eq!(PLAN.take(), Some((Stage::BeforePayload, false)));
        assert_eq!(result, Err(Error::Authentication));
        assert_eq!(dst, before);
        assert_eq!(work, [0; 1501]);
        rx.open(nonce, &aad, &tag, &ct, &mut dst, &mut work)?;
        assert_eq!(dst, plain);
    }
    Ok(())
}

#[test]
fn pair_interruptions_retire_without_commit_or_nonce_reuse() -> Result<(), Error> {
    if probe()?.is_none() {
        return Ok(());
    }
    let key = [0xc7; 32];
    let plain = [0x63; 1057];
    let mut ct = plain;
    let mut work = [0; 1057];
    let new = || Sealer::from_reserved_range(&key, *b"pair", u64::MAX - 1, 2);
    let (nonce, tag) = new()?.seal_in_place(b"aad", &mut ct, &mut work)?;
    for stage in [
        Stage::BeforePayload,
        Stage::AfterPayload,
        Stage::AfterDerivation,
        Stage::AfterFraming,
        Stage::BeforeCommit,
    ] {
        for unwind in [false, true] {
            for sealing in [false, true] {
                for in_place in [false, true] {
                    let mut cpu = probe()?.ok_or(Error::Invariant)?;
                    let mut sender = new()?;
                    let before = if !in_place {
                        [0x43; 1057]
                    } else if sealing {
                        plain
                    } else {
                        ct
                    };
                    let mut dst = before;
                    work.fill(0x46);
                    PLAN.set(Some((stage, unwind)));
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        if sealing {
                            let mut s = sender.with_pair(&mut cpu)?;
                            if in_place {
                                s.seal_in_place(b"aad", &mut dst, &mut work).map(drop)
                            } else {
                                s.seal(b"aad", &plain, &mut dst, &mut work).map(drop)
                            }
                        } else {
                            let mut r = Opener::new(&key).with_pair(&mut cpu)?;
                            if in_place {
                                r.open_in_place(nonce, b"aad", &tag, &mut dst, &mut work)
                            } else {
                                r.open(nonce, b"aad", &tag, &ct, &mut dst, &mut work)
                            }
                        }
                    }));
                    assert_eq!(PLAN.take(), None);
                    match result {
                        Ok(v) => {
                            assert!(!unwind);
                            assert_eq!(v, Err(Error::Invariant));
                        }
                        Err(payload) => {
                            assert!(unwind);
                            assert_eq!(payload.downcast_ref::<Stage>(), Some(&stage));
                        }
                    }
                    assert_eq!(dst, before);
                    assert_eq!(work, [0; 1057]);
                    assert!(matches!(sender.with_pair(&mut cpu), Err(Error::Invariant)));
                    assert!(matches!(
                        Opener::new(&key).with_pair(&mut cpu),
                        Err(Error::Invariant)
                    ));
                    if sealing {
                        let mut next_cpu = probe()?.ok_or(Error::Invariant)?;
                        let mut rebound = sender.with_pair(&mut next_cpu)?;
                        let (next, _) = rebound.seal_in_place(b"", &mut [], &mut [])?;
                        assert_eq!(next.split_at(4).1, u64::MAX.to_be_bytes());
                        assert_eq!(
                            rebound.seal_in_place(b"", &mut [], &mut []),
                            Err(Error::Exhausted)
                        );
                    }
                }
            }
        }
    }
    Ok(())
}
