//! Official vectors, consuming lifecycle, canonicalization and failure acceptance.
use brynja_legacy_md5::{
    BitString, HardenedMd5, Md5, Md5Error, PublicDeclassification, md5, md5_bits,
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
fn official_rfc_vectors_ordinary_hardened_and_streamed() {
    let mut count = 0_usize;
    for line in include_str!("vectors/rfc1321.txt")
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
                md5_bits(input).map(|digest| digest.to_vec()),
                Ok(expected.clone())
            );
            let mut output = [0xa5; 16];
            assert_eq!(
                HardenedMd5::new().finalize_bits_public(
                    input,
                    &mut output,
                    PublicDeclassification::acknowledge()
                ),
                Ok(())
            );
            assert_eq!(output.as_slice(), expected);
            let (complete, partial) = input.split();
            for partition in [1, 7, 63, 64, 65] {
                let mut state = Md5::new();
                let mut hardened = HardenedMd5::new();
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
                    assert_eq!(output, [0; 16]);
                }
            }
            if input.is_byte_aligned() {
                assert_eq!(md5(&message).map(|digest| digest.to_vec()), Ok(expected));
            }
        }
        count = count.saturating_add(1);
    }
    assert_eq!(count, 7);
}

#[test]
fn standard_byte_vectors_and_million_a() {
    for (message, expected) in [
        (b"".as_slice(), "d41d8cd98f00b204e9800998ecf8427e"),
        (b"abc", "900150983cd24fb0d6963f7d28e17f72"),
        (
            b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
            "8215ef0796a20bcaaae116d3876c664a",
        ),
    ] {
        assert_eq!(
            md5(message).map(|digest| digest.to_vec()),
            Ok(decode(expected))
        );
    }
    let mut state = Md5::new();
    for _ in 0..1000 {
        assert_eq!(state.update(&[b'a'; 1000]), Ok(()));
    }
    assert_eq!(
        state.finalize().as_slice(),
        decode("7707d6ae4e027c70eea2a935c2296f21")
    );
}

#[test]
fn output_failures_are_atomic_or_clear_complete_secret_destination() {
    for size in [0, 1, 15, 17, 128] {
        let mut destination = vec![0xa5; size];
        assert_eq!(
            HardenedMd5::new()
                .finalize_public(&mut destination, PublicDeclassification::acknowledge()),
            Err(Md5Error::OutputLength)
        );
        assert!(destination.iter().all(|byte| *byte == 0xa5));
        assert!(matches!(
            HardenedMd5::digest_secret(b"secret", &mut destination),
            Err(Md5Error::OutputLength)
        ));
        assert!(destination.iter().all(|byte| *byte == 0));
    }
    let mut output = [0xa5; 16];
    {
        let secret = HardenedMd5::digest_secret(b"abc", &mut output);
        assert!(secret.is_ok());
        if let Ok(secret) = secret {
            assert_eq!(secret.expose(), decode("900150983cd24fb0d6963f7d28e17f72"));
        }
    }
    assert_eq!(output, [0; 16]);
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
    let mut state = Md5::new();
    assert_eq!(state.update(b"abc"), Ok(()));
    assert_eq!(state.message_bits(), 24);
    assert_eq!(
        state.check_additional_bits(u128::MAX),
        Err(Md5Error::MessageTooLong)
    );
    assert_eq!(state.update(&[]), Ok(()));
    assert_eq!(state.finalize(), md5(b"abc").unwrap_or_default());
}

#[test]
fn recoverable_unwind_clears_typed_secret_output() {
    let mut output = [0xa5; 16];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let mut state = HardenedMd5::new();
        assert_eq!(state.update(b"secret"), Ok(()));
        let secret = HardenedMd5::digest_secret(b"abc", &mut output);
        assert!(secret.is_ok());
        // The failed assertion is intentional test-only recoverable unwinding.
        assert_eq!(1, 2);
        drop(secret);
        drop(state);
    }));
    assert!(result.is_err());
    assert_eq!(output, [0; 16]);
}

#[test]
fn dynamic_analysis_covers_padding_and_partial_bit_boundaries() {
    for length in [0, 1, 55, 56, 63, 64, 65] {
        let bytes = vec![0x80; length];
        for width in 1..=8 {
            let input = BitString::new(&bytes, if length == 0 { 0 } else { width });
            assert!(input.is_ok());
            if let Ok(input) = input {
                let expected = md5_bits(input);
                assert!(expected.is_ok());
                let mut output = [0xa5; 16];
                {
                    let result = HardenedMd5::digest_bits_secret(input, &mut output);
                    assert!(result.is_ok());
                    if let Ok(secret) = result {
                        assert_eq!(secret.expose(), expected.unwrap_or_default());
                    }
                }
                assert_eq!(output, [0; 16]);
            }
        }
    }
}
