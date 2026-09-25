use super::*;
use brynja_legacy_sha1::{BitString, sha1, sha1_bits};

fn cleared(session: &Session) {
    assert!(session.output.as_bytes().iter().all(|b| *b == 0));
}
fn expected(input: &[u8], valid: u8) -> Result<[u8; 20], Error> {
    sha1_bits(BitString::new(input, valid).map_err(|_| Error::InvalidBits)?)
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
        [
            0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad,
            0x27, 0x31, 0x65, 0x34, 0x01, 0x6f
        ]
    );
    Ok(())
}
#[test]
fn official_nist_bit_vectors() -> Result<(), Error> {
    let mut session = Session::new(limits())?;
    let data = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/vectors/nist.txt"
    ))
    .map_err(|_| Error::Invariant)?;
    let mut count = 0usize;
    for line in data
        .lines()
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
    {
        let columns: Vec<&str> = line.split('|').collect();
        let bits = columns
            .first()
            .ok_or(Error::Invariant)?
            .parse::<usize>()
            .map_err(|_| Error::Invariant)?;
        let input = hex(columns.get(1).ok_or(Error::Invariant)?)?;
        let output = hex(columns.get(2).ok_or(Error::Invariant)?)?;
        let used = bits.div_ceil(8);
        let valid = if bits == 0 {
            0
        } else {
            u8::try_from((bits - 1) % 8 + 1).map_err(|_| Error::Invariant)?
        };
        assert_eq!(
            session
                .hash_chunks(
                    &[],
                    input.get(..used).ok_or(Error::Invariant)?,
                    valid,
                    &Cancellation::new()
                )?
                .expose(),
            output
        );
        count = count.checked_add(1).ok_or(Error::Invariant)?;
    }
    assert_eq!(count, 529);
    Ok(())
}
fn hex(text: &str) -> Result<Vec<u8>, Error> {
    if text == "-" {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for bytes in text.as_bytes().chunks(2) {
        let text = core::str::from_utf8(bytes).map_err(|_| Error::Invariant)?;
        out.push(u8::from_str_radix(text, 16).map_err(|_| Error::Invariant)?);
    }
    Ok(out)
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
            sha1(b"abc").map_err(|_| Error::Invariant)?
        );
    }
    let mut wrong = [0xa5; 19];
    assert_eq!(
        session
            .hash(b"abc")?
            .declassify(&mut wrong, PublicDeclassification::acknowledge()),
        Err(Error::OutputLength)
    );
    assert_eq!(wrong, [0xa5; 19]);
    cleared(&session);
    let mut public = [0; 20];
    session
        .hash(b"abc")?
        .declassify(&mut public, PublicDeclassification::acknowledge())?;
    assert_eq!(public, sha1(b"abc").map_err(|_| Error::Invariant)?);
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
            sha1(b"reuse").map_err(|_| Error::Invariant)?
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
