use super::*;
use brynja_legacy_md5::{BitString, md5, md5_bits};

fn cleared(session: &Session) {
    assert!(session.output.as_bytes().iter().all(|b| *b == 0));
}
fn expected(input: &[u8], valid: u8) -> Result<[u8; 16], Error> {
    md5_bits(BitString::new(input, valid).map_err(|_| Error::InvalidBits)?)
        .map_err(|_| Error::Invariant)
}
#[test]
fn bit_padding_and_chunk_boundaries_match_portable() -> Result<(), Error> {
    let mut session = Session::new(limits())?;
    for len in [
        0usize, 1, 7, 55, 56, 57, 63, 64, 65, 119, 120, 127, 128, 129, 4095, 4096, 4097,
    ] {
        for valid in 1u8..=8 {
            let mut input: Vec<u8> = (0..=250).cycle().take(len).collect();
            if let Some(last) = input.last_mut() {
                *last &= u8::MAX << (8 - valid);
            }
            let valid = if input.is_empty() { 0 } else { valid };
            let digest = expected(&input, valid)?;
            for split in [0, len.saturating_sub(1).min(17), len.saturating_sub(1)] {
                let (head, tail) = input.split_at(split);
                let output =
                    session.hash_chunks(&[&[], head, &[]], tail, valid, &Cancellation::new())?;
                assert_eq!(output.expose(), digest);
                drop(output);
                cleared(&session);
            }
        }
    }
    let input = vec![b'a'; 1_000_000];
    assert_eq!(
        session.hash(&input)?.expose(),
        hex("7707d6ae4e027c70eea2a935c2296f21")?
    );
    Ok(())
}
#[test]
fn rfc1321_byte_vectors() -> Result<(), Error> {
    let mut session = Session::new(limits())?;
    for (input, digest) in [
        ("", "d41d8cd98f00b204e9800998ecf8427e"),
        ("a", "0cc175b9c0f1b6a831c399e269772661"),
        ("abc", "900150983cd24fb0d6963f7d28e17f72"),
        ("message digest", "f96b697d7cb7938d525a2f31aaf161d0"),
        (
            "abcdefghijklmnopqrstuvwxyz",
            "c3fcd3d76192e4007dfb496cca67e13b",
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
            "d174ab98d277d9f5a5611c2c9f419d9f",
        ),
        (
            "12345678901234567890123456789012345678901234567890123456789012345678901234567890",
            "57edf4a22be3c955ac49da2e2107b67a",
        ),
    ] {
        assert_eq!(session.hash(input.as_bytes())?.expose(), hex(digest)?);
    }
    Ok(())
}
fn hex(text: &str) -> Result<Vec<u8>, Error> {
    text.as_bytes()
        .chunks(2)
        .map(|pair| {
            let pair = core::str::from_utf8(pair).map_err(|_| Error::Invariant)?;
            u8::from_str_radix(pair, 16).map_err(|_| Error::Invariant)
        })
        .collect()
}
#[test]
fn rejection_forgotten_loans_and_exact_public_release() -> Result<(), Error> {
    let mut session = Session::new(limits())?;
    for case in 0..6 {
        core::mem::forget(session.hash(b"previous secret")?);
        let cancel = Cancellation::new();
        let result = match case {
            0 => session.hash_chunks(&[], &[0xff], 3, &cancel),
            1 => session.hash_chunks(&[], &[], 8, &cancel),
            2 => session.hash_chunks(&[], &[0], 0, &cancel),
            3 => {
                cancel.cancel();
                session.hash_chunks(&[b"abc"], &[], 0, &cancel)
            }
            4 => {
                session.limits.max_message_bits = 7;
                session.hash(b"abc")
            }
            _ => {
                session.limits.max_chunks = 1;
                session.hash_chunks(&[&[], &[]], &[], 0, &cancel)
            }
        };
        assert!(result.is_err());
        drop(result);
        cleared(&session);
        session.limits = limits();
        assert_eq!(
            session.hash(b"abc")?.expose(),
            md5(b"abc").map_err(|_| Error::Invariant)?
        );
    }
    let mut wrong = [0xa5; 15];
    assert_eq!(
        session
            .hash(b"abc")?
            .declassify(&mut wrong, PublicDeclassification::acknowledge()),
        Err(Error::OutputLength)
    );
    assert_eq!(wrong, [0xa5; 15]);
    cleared(&session);
    let mut public = [0; 16];
    session
        .hash(b"abc")?
        .declassify(&mut public, PublicDeclassification::acknowledge())?;
    assert_eq!(public, md5(b"abc").map_err(|_| Error::Invariant)?);
    cleared(&session);
    Ok(())
}
#[test]
fn bounded_cancellation_and_post_write_unwind_clear_and_reuse() -> Result<(), Error> {
    let mut session = Session::new(limits())?;
    let input = vec![0x5a; 8193];
    for point in 0..8 {
        session.fault = Fault::CancelAt(point);
        assert_eq!(session.hash(&input).err(), Some(Error::Cancelled));
        cleared(&session);
        session.fault = Fault::None;
        assert_eq!(
            session.hash(b"reuse")?.expose(),
            md5(b"reuse").map_err(|_| Error::Invariant)?
        );
    }
    session.fault = Fault::CancelAt(8);
    assert!(session.hash(&input).is_ok());
    session.fault = Fault::PanicAfterWrite(0);
    assert_eq!(
        session.hash(b"secret").err(),
        Some(Error::Resource(protected_memory::Error::WorkerPanicked))
    );
    cleared(&session);
    session.fault = Fault::None;
    assert!(session.hash(b"reuse").is_ok());
    Ok(())
}
#[test]
fn actual_workspace_staging_output_protections_and_resource_errors() -> Result<(), Error> {
    let mut session = Session::new(limits())?;
    session.fault = Fault::VerifyStorage;
    verify_mapping(session.output.as_bytes());
    assert!(session.hash(b"protected").is_ok());
    let mut invalid = limits();
    invalid.max_output_mapping_bytes = 1;
    assert!(Session::new(invalid).is_err());
    invalid = limits();
    invalid.stack_bytes = 65535;
    assert!(Session::new(invalid).is_err());
    invalid = limits();
    invalid.max_chunks = 0;
    assert!(matches!(Session::new(invalid), Err(Error::InvalidLimits)));
    Ok(())
}
