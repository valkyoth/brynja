use super::*;
use brynja_legacy_sha1::{BitString, sha1_bits};
#[test]
fn official_nist_bit_vectors() -> Result<(), Error> {
    let mut session = CompiledSession::new(limits())?;
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
fn clear(s: &CompiledSession) {
    assert!(s.inner.output.as_bytes().iter().all(|b| *b == 0));
}
#[test]
fn native_required_route_bits_padding_and_million_bytes() -> Result<(), Error> {
    let mut s = CompiledSession::new(limits())?;
    #[cfg(target_arch = "x86_64")]
    assert_eq!(s.backend(), Sha1Backend::X86Sha);
    #[cfg(target_arch = "aarch64")]
    assert_eq!(s.backend(), Sha1Backend::Aarch64Sha1);
    let mut count = 0;
    for length in [
        0usize, 1, 55, 56, 63, 64, 65, 119, 120, 127, 128, 4095, 4096, 4097,
    ] {
        for valid in 1u8..=8 {
            let mut bytes = vec![0x93; length];
            if let Some(last) = bytes.last_mut() {
                *last &= u8::MAX << (8 - valid);
            }
            let valid = if length == 0 { 0 } else { valid };
            let expected = sha1_bits(BitString::new(&bytes, valid).map_err(|_| Error::Invariant)?)
                .map_err(|_| Error::Invariant)?;
            for split in [
                0,
                length.saturating_sub(1).min(19),
                length.saturating_sub(1),
            ] {
                let (prefix, tail) = bytes.split_at_checked(split).ok_or(Error::Invariant)?;
                assert_eq!(
                    s.hash_chunks(&[&[], prefix, &[]], tail, valid, &Cancellation::new())?
                        .expose(),
                    expected
                );
                clear(&s);
                count += 1;
            }
        }
    }
    assert_eq!(count, 336);
    assert_eq!(
        s.hash(&vec![b'a'; 1_000_000])?.expose(),
        [
            0x34, 0xaa, 0x97, 0x3c, 0xd4, 0xc4, 0xda, 0xa4, 0xf6, 0x1e, 0xeb, 0x2b, 0xdb, 0xad,
            0x27, 0x31, 0x65, 0x34, 0x01, 0x6f
        ]
    );
    println!(
        "STRICT_SHA1_COMPILED: {:?}; differential={count}",
        s.backend()
    );
    Ok(())
}
#[test]
fn failures_clear_protected_output_and_classify_executor_reuse() -> Result<(), Error> {
    for point in [
        Boundary::Setup,
        Boundary::Update,
        Boundary::Finalize,
        Boundary::Output,
    ] {
        for fault in [
            Fault::Cancel(point),
            Fault::Revoke(point),
            Fault::Panic(point),
        ] {
            let mut s = CompiledSession::new(limits())?;
            s.fault = fault;
            assert!(s.hash(b"secret input").is_err());
            clear(&s);
            let terminal = !matches!(fault, Fault::Cancel(_));
            assert_eq!(s.is_quarantined(), terminal);
            s.fault = Fault::None;
            if terminal {
                assert!(matches!(s.hash(b"reuse"), Err(Error::Quarantined)));
            } else {
                drop(s.hash(b"reuse")?);
            }
            clear(&s);
        }
    }
    let mut s = CompiledSession::new(limits())?;
    for case in 0..5 {
        core::mem::forget(s.hash(b"previous secret")?);
        let cancel = Cancellation::new();
        let result = match case {
            0 => s.hash_chunks(&[], &[0xff], 1, &cancel),
            1 => s.hash_chunks(&[], &[], 8, &cancel),
            2 => {
                cancel.cancel();
                s.hash_chunks(&[], &[], 0, &cancel)
            }
            3 => {
                s.inner.limits.max_chunks = 0;
                s.hash(b"a")
            }
            _ => {
                s.inner.limits.max_message_bits = 0;
                s.hash(b"a")
            }
        };
        assert!(result.is_err());
        drop(result);
        clear(&s);
        assert!(!s.is_quarantined());
        s.inner.limits = limits();
    }
    core::mem::forget(s.hash(b"last secret")?);
    s.quarantine();
    clear(&s);
    assert!(matches!(s.hash(b""), Err(Error::Quarantined)));
    Ok(())
}
