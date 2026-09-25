use super::*;
use brynja_legacy_md5::{BitString, Md5BatchError, md5_bits};
fn clear(s: &Session) {
    assert!(s.output.as_bytes().iter().all(|b| *b == 0));
}
#[test]
fn required_simd_matches_all_lanes_bits_and_boundaries() -> Result<(), Error> {
    let mut session = Session::new(limits())?;
    let mut count = 0;
    for length in [64usize, 65, 119, 120, 127, 128, 129, 4097] {
        for valid in 1..=8 {
            let inputs: [Vec<u8>; 8] = core::array::from_fn(|lane| {
                let mut v = vec![0x30; length + lane];
                if let Some(last) = v.last_mut() {
                    *last &= u8::MAX << (8 - valid);
                }
                v
            });
            let raw = inputs.each_ref().map(|bytes| {
                Some(Input {
                    bytes,
                    valid_bits: valid,
                })
            });
            // A 64-byte descriptor with a fractional final byte has only 63
            // complete bytes; the eight-lane x86 group is intentionally ineligible.
            if length == 64 && valid < 8 && cfg!(target_arch = "x86_64") {
                assert!(matches!(
                    session.digest(&raw, 10000, &Cancellation::new()),
                    Err(Error::Execution(api::Error::IneligibleWorkload))
                ));
                assert!(!session.is_quarantined());
                clear(&session);
                continue;
            }
            let output = session.digest(&raw, 10000, &Cancellation::new())?;
            assert_eq!(output.report().backend, Some(session_backend()));
            assert!(output.report().work.vector_blocks > 0);
            for (slot, bytes) in output.expose().chunks_exact(16).zip(&inputs) {
                let expected =
                    md5_bits(BitString::new(bytes, valid).map_err(|_| Error::InvalidBits)?)
                        .map_err(|_| Error::Invariant)?;
                assert_eq!(slot, expected);
                count += 1;
            }
            drop(output);
            clear(&session);
        }
    }
    assert_eq!(
        count,
        if cfg!(target_arch = "x86_64") {
            456
        } else {
            512
        }
    );
    println!(
        "STRICT_MD5_BATCH: {:?}; differential={count}",
        session.backend()
    );
    Ok(())
}
fn session_backend() -> Md5Backend {
    #[cfg(target_arch = "x86_64")]
    {
        Md5Backend::X86Avx2
    }
    #[cfg(target_arch = "aarch64")]
    {
        Md5Backend::Aarch64Neon
    }
}
#[test]
fn work_rejection_cancellation_revocation_and_unwind_clear_all_slots() -> Result<(), Error> {
    let input = [0x36; 129];
    let raw = core::array::from_fn(|_| Some(Input::bytes(&input)));
    let mut s = Session::new(limits())?;
    for budget in 0..24 {
        assert!(matches!(
            s.digest(&raw, budget, &Cancellation::new()),
            Err(Error::Execution(api::Error::Batch(
                Md5BatchError::WorkLimit
            )))
        ));
        clear(&s);
        assert!(!s.is_quarantined());
        drop(s.digest(&raw, 24, &Cancellation::new())?);
        clear(&s);
    }
    for point in [0, 1, 2, usize::MAX] {
        for fault in [
            Fault::Cancel(point),
            Fault::Revoke(point),
            Fault::Panic(point),
        ] {
            let mut s = Session::new(limits())?;
            s.fault = fault;
            assert!(s.digest(&raw, 1000, &Cancellation::new()).is_err());
            clear(&s);
            let terminal = !matches!(fault, Fault::Cancel(_));
            assert_eq!(s.is_quarantined(), terminal);
            s.fault = Fault::None;
            if terminal {
                assert!(matches!(
                    s.digest(&raw, 1000, &Cancellation::new()),
                    Err(Error::Quarantined)
                ));
            } else {
                drop(s.digest(&raw, 1000, &Cancellation::new())?);
            }
            clear(&s);
        }
    }
    Ok(())
}
#[test]
fn noncanonical_ineligible_forgotten_and_inactive_output_are_safe() -> Result<(), Error> {
    let input = [0x42; 128];
    let raw = core::array::from_fn(|_| Some(Input::bytes(&input)));
    let mut s = Session::new(limits())?;
    core::mem::forget(s.digest(&raw, 100, &Cancellation::new())?);
    let bad = core::array::from_fn(|_| {
        Some(Input {
            bytes: &[0xff],
            valid_bits: 1,
        })
    });
    assert!(matches!(
        s.digest(&bad, 100, &Cancellation::new()),
        Err(Error::InvalidBits)
    ));
    clear(&s);
    assert!(!s.is_quarantined());
    let empty = core::array::from_fn(|_| Some(Input::bytes(b"")));
    assert!(matches!(
        s.digest(&empty, 100, &Cancellation::new()),
        Err(Error::Execution(api::Error::IneligibleWorkload))
    ));
    clear(&s);
    assert!(!s.is_quarantined());
    // NEON can form a four-lane group while leaving four truly inactive slots.
    #[cfg(target_arch = "aarch64")]
    {
        let half = core::array::from_fn(|i| {
            if i < 4 {
                Some(Input::bytes(&input))
            } else {
                None
            }
        });
        let output = s.digest(&half, 100, &Cancellation::new())?;
        assert!(output.expose()[64..].iter().all(|b| *b == 0));
    }
    let mut wrong = [0xa5; 127];
    assert_eq!(
        s.digest(&raw, 100, &Cancellation::new())?
            .declassify(&mut wrong, PublicDeclassification::acknowledge()),
        Err(Error::OutputLength)
    );
    assert_eq!(wrong, [0xa5; 127]);
    clear(&s);
    core::mem::forget(s.digest(&raw, 100, &Cancellation::new())?);
    s.quarantine();
    clear(&s);
    assert!(matches!(
        s.digest(&raw, 100, &Cancellation::new()),
        Err(Error::Quarantined)
    ));
    Ok(())
}
