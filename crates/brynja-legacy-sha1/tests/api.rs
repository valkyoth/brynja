//! Official vectors, consuming lifecycle, canonicalization and failure acceptance.
use brynja_legacy_sha1::{
    BitString, HardenedSha1, PublicDeclassification, Sha1, Sha1Error, sha1, sha1_bits,
};

fn decode(text: &str) -> Vec<u8> {
    if text == "-" {
        return Vec::new();
    }
    assert_eq!(text.len() % 2, 0);
    let result: Result<Vec<_>, _> = text
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| {
            let encoded = core::str::from_utf8(chunk).unwrap_or_default();
            u8::from_str_radix(encoded, 16)
        })
        .collect();
    assert!(result.is_ok());
    result.unwrap_or_default()
}

#[test]
fn official_nist_vectors_ordinary_hardened_and_streamed() {
    let mut count = 0_usize;
    for line in include_str!("vectors/nist.txt")
        .lines()
        .filter(|line| !line.starts_with('#'))
    {
        let mut fields = line.split('|');
        let length = fields.next().unwrap_or_default().parse::<usize>();
        assert!(length.is_ok());
        let length = length.unwrap_or_default();
        let message = decode(fields.next().unwrap_or_default());
        let expected = decode(fields.next().unwrap_or_default());
        assert!(fields.next().is_none());
        let width = if message.is_empty() {
            0
        } else if length % 8 == 0 {
            8
        } else {
            u8::try_from(length % 8).unwrap_or(0)
        };
        let input = BitString::new(&message, width);
        assert!(input.is_ok());
        if let Ok(input) = input {
            assert_eq!(
                sha1_bits(input).map(|digest| digest.to_vec()),
                Ok(expected.clone())
            );
            let mut output = [0xa5; 20];
            assert_eq!(
                HardenedSha1::new().finalize_bits_public(
                    input,
                    &mut output,
                    PublicDeclassification::acknowledge()
                ),
                Ok(())
            );
            assert_eq!(output.as_slice(), expected);
            let (complete, partial) = input.split();
            for partition in [1, 7, 63, 64, 65] {
                let mut state = Sha1::new();
                let mut hardened = HardenedSha1::new();
                for chunk in complete.chunks(partition) {
                    assert_eq!(state.update(chunk), Ok(()));
                    assert_eq!(hardened.update(chunk), Ok(()));
                }
                let (byte, valid) = partial.unwrap_or((0, 0));
                let tail_bytes = [byte];
                let tail = BitString::new(if valid == 0 { &[] } else { &tail_bytes }, valid);
                assert!(tail.is_ok());
                if let Ok(tail) = tail {
                    assert_eq!(
                        state.finalize_bits(tail).map(|digest| digest.to_vec()),
                        Ok(expected.clone())
                    );
                    {
                        let secret = hardened.finalize_bits_secret(tail, &mut output);
                        assert!(secret.is_ok());
                        if let Ok(secret) = secret {
                            assert_eq!(secret.expose(), expected);
                        }
                    }
                    assert_eq!(output, [0; 20]);
                }
            }
            if input.is_byte_aligned() {
                assert_eq!(sha1(&message).map(|digest| digest.to_vec()), Ok(expected));
            }
        }
        count = count.saturating_add(1);
    }
    assert_eq!(count, 529);
}

#[test]
fn standard_byte_vectors_and_million_a() {
    for (message, expected) in [
        (b"".as_slice(), "da39a3ee5e6b4b0d3255bfef95601890afd80709"),
        (b"abc", "a9993e364706816aba3e25717850c26c9cd0d89d"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1",
        ),
    ] {
        assert_eq!(
            sha1(message).map(|digest| digest.to_vec()),
            Ok(decode(expected))
        );
    }
    let mut state = Sha1::new();
    for _ in 0..1000 {
        assert_eq!(state.update(&[b'a'; 1000]), Ok(()));
    }
    assert_eq!(
        state.finalize().as_slice(),
        decode("34aa973cd4c4daa4f61eeb2bdbad27316534016f")
    );
}

#[test]
fn output_failures_are_atomic_or_clear_complete_secret_destination() {
    for size in [0, 1, 19, 21, 128] {
        let mut destination = vec![0xa5; size];
        assert_eq!(
            HardenedSha1::new()
                .finalize_public(&mut destination, PublicDeclassification::acknowledge()),
            Err(Sha1Error::OutputLength)
        );
        assert!(destination.iter().all(|byte| *byte == 0xa5));
        assert!(matches!(
            HardenedSha1::digest_secret(b"secret", &mut destination),
            Err(Sha1Error::OutputLength)
        ));
        assert!(destination.iter().all(|byte| *byte == 0));
    }
    let mut output = [0xa5; 20];
    {
        let secret = HardenedSha1::digest_secret(b"abc", &mut output);
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(
                secret.expose(),
                decode("a9993e364706816aba3e25717850c26c9cd0d89d")
            );
        }
    }
    assert_eq!(output, [0; 20]);
}

#[test]
fn canonical_tails_and_capacity_probes() {
    assert!(BitString::new(&[], 1).is_err());
    for width in 0..=9 {
        if !(1..=8).contains(&width) {
            assert!(BitString::new(&[0], width).is_err());
        }
    }
    for width in 1..8 {
        assert!(BitString::new(&[1], width).is_err());
    }
    let mut state = Sha1::new();
    assert_eq!(state.update(b"abc"), Ok(()));
    assert_eq!(state.message_bits(), 24);
    assert_eq!(
        state.check_additional_bits(u64::MAX),
        Err(Sha1Error::MessageTooLong)
    );
    assert_eq!(state.update(&[]), Ok(()));
    assert_eq!(state.finalize(), sha1(b"abc").unwrap_or_default());
}

#[test]
fn recoverable_unwind_clears_typed_secret_output() {
    let mut output = [0xa5; 20];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut state = HardenedSha1::new();
        assert_eq!(state.update(b"secret"), Ok(()));
        let secret = HardenedSha1::digest_secret(b"abc", &mut output);
        assert!(secret.is_ok());
        // The failed assertion is intentional test-only recoverable unwinding.
        assert_eq!(1, 2);
        drop(secret);
        drop(state);
    }));
    assert!(result.is_err());
    assert_eq!(output, [0; 20]);
}

#[test]
fn dynamic_analysis_covers_padding_and_partial_bit_boundaries() {
    for length in [0, 1, 55, 56, 63, 64, 65] {
        let bytes = vec![0x80; length];
        for width in 1..=8 {
            let input = BitString::new(&bytes, if length == 0 { 0 } else { width });
            assert!(input.is_ok());
            if let Ok(input) = input {
                let expected = sha1_bits(input);
                assert!(expected.is_ok());
                let mut output = [0xa5; 20];
                {
                    let result = HardenedSha1::digest_bits_secret(input, &mut output);
                    assert!(result.is_ok());
                    if let Ok(secret) = result {
                        assert_eq!(secret.expose(), expected.unwrap_or_default());
                    }
                }
                assert_eq!(output, [0; 20]);
            }
        }
    }
}
