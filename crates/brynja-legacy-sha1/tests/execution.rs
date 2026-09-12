//! Operational public API acceptance, without evidence-only features or cfgs.
#![cfg(feature = "execution")]
use brynja_legacy_sha1::{
    BitString, Sha1BackendHealth,
    execution::{Error, Executor, Mode, PublicData},
    sha1,
};

fn owners() -> [Executor; 2] {
    let preferred = Executor::for_compiled_target(Mode::Prefer);
    assert!(preferred.is_ok());
    [
        Executor::portable(),
        preferred.unwrap_or_else(|_| Executor::portable()),
    ]
}

fn decode(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    assert_eq!(text.len() % 2, 0);
    text.as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = core::str::from_utf8(pair);
            assert!(text.is_ok());
            let byte = u8::from_str_radix(text.unwrap_or_default(), 16);
            assert!(byte.is_ok());
            byte.unwrap_or_default()
        })
        .collect()
}

#[test]
fn all_529_nist_vectors_one_shot_and_partitioned_operational_routes() -> Result<(), Error> {
    for owner in owners() {
        let mut count = 0;
        for line in include_str!("vectors/nist.txt")
            .lines()
            .filter(|s| !s.starts_with('#'))
        {
            let fields: Vec<_> = line.split('|').collect();
            assert_eq!(fields.len(), 3);
            let [length, message, expected] = fields.as_slice() else {
                return Err(Error::MessageTooLong);
            };
            let length = length.parse::<usize>();
            assert!(length.is_ok());
            let length = length.unwrap_or_default();
            let message = decode(message);
            let expected = decode(expected);
            let valid = if message.is_empty() {
                0
            } else if length % 8 == 0 {
                8
            } else {
                u8::try_from(length % 8).unwrap_or_default()
            };
            let bits = BitString::new(&message, valid).map_err(|_| Error::MessageTooLong)?;
            assert_eq!(
                owner.hash_bits(bits, PublicData::acknowledge())?.as_slice(),
                expected
            );
            let (bytes, partial) = bits.split();
            for width in [1, 7, 63, 64, 65, 257] {
                let mut stream = owner.start(PublicData::acknowledge())?;
                for chunk in bytes.chunks(width) {
                    stream.update(chunk)?;
                    stream.update(&[])?;
                }
                let (last, valid) = partial.unwrap_or((0, 0));
                let tail = [last];
                let tail = BitString::new(if valid == 0 { &[] } else { &tail }, valid)
                    .map_err(|_| Error::MessageTooLong)?;
                assert_eq!(stream.finalize_bits(tail)?.as_slice(), expected);
            }
            count += 1;
        }
        assert_eq!(count, 529);
    }
    Ok(())
}

#[test]
fn million_byte_and_byte_one_shot_match_standard() -> Result<(), Error> {
    for owner in owners() {
        assert_eq!(
            Ok(owner.hash(b"abc", PublicData::acknowledge())?),
            sha1(b"abc")
        );
        let mut stream = owner.start(PublicData::acknowledge())?;
        for _ in 0..1000 {
            stream.update(&[b'a'; 1000])?;
        }
        assert_eq!(stream.message_bits()?, 8_000_000);
        assert_eq!(
            stream.finalize()?.as_slice(),
            decode("34aa973cd4c4daa4f61eeb2bdbad27316534016f")
        );
    }
    Ok(())
}

#[test]
fn revocation_empty_updates_capacity_and_finalization_fail_closed() -> Result<(), Error> {
    for owner in owners() {
        let mut state = owner.start(PublicData::acknowledge())?;
        state.update(b"abc")?;
        assert_eq!(
            state.check_additional_bits(u64::MAX),
            Err(Error::MessageTooLong)
        );
        assert_eq!(state.message_bits()?, 24);
        let other = owner.start(PublicData::acknowledge())?;
        owner.quarantine();
        assert_eq!(owner.report().health, Sha1BackendHealth::Quarantined);
        assert_eq!(state.update(&[]), Err(Error::Quarantined));
        assert!(state.finalize().is_err());
        assert!(other.finalize().is_err());
        assert!(owner.hash(b"", PublicData::acknowledge()).is_err());
    }
    Ok(())
}

#[test]
fn static_execution_is_not_candidate_admission() -> Result<(), Error> {
    let preferred = Executor::for_compiled_target(Mode::Prefer)?;
    if let Some(backend) = preferred.report().backend {
        assert!(!backend.is_admitted());
        let required = Executor::for_compiled_target(Mode::Require)?;
        assert_eq!(required.report().backend, Some(backend));
        assert_eq!(
            Ok(required.hash(b"abc", PublicData::acknowledge())?),
            sha1(b"abc")
        );
        println!(
            "SHA1_OPERATIONAL: {}; normal build; public only",
            backend.as_str()
        );
    } else {
        assert!(Executor::for_compiled_target(Mode::Require).is_err());
    }
    Ok(())
}
