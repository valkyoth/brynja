//! NIST AES_GCM.pdf: encrypt-generate and decrypt-verify, examples 1–6.
//! Repeated key/IV pairs here reproduce *public fixtures*, not safe sender usage.
use aes_gcm_consumer::crypto::aes_gcm::{Aes128Gcm, Aes192Gcm, Aes256Gcm, GcmError};

fn hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    let (pairs, rest) = s.as_bytes().as_chunks::<2>();
    assert!(rest.is_empty());
    pairs
        .iter()
        .map(|p| u8::from_str_radix(str::from_utf8(p).expect("ASCII"), 16).expect("fixture hex"))
        .collect()
}

macro_rules! campaign {
    ($test:ident, $name:ident, $width:literal, $schedule:literal) => {
        #[test]
        fn $test() -> Result<(), GcmError> {
            let mut seen = 0;
            for row in include_str!("nist-worked.txt").lines() {
                let [bits, number, k, iv, aad, p, c, t]: [&str; 8] = row
                    .split_ascii_whitespace()
                    .collect::<Vec<_>>()
                    .try_into()
                    .expect("fields");
                if bits != $width {
                    continue;
                }
                seen += 1;
                assert_eq!(number.parse::<usize>().expect("example number"), seen);
                let (key, iv, aad, plain, ciphertext, tag) =
                    (hex(k), hex(iv), hex(aad), hex(p), hex(c), hex(t));
                let iv: [u8; 12] = iv.try_into().expect("96-bit fixture IV");
                let (prefix, invocation) = iv.split_at(4);
                let (mut schedule, mut work) = ([0; $schedule], vec![0x77; plain.len()]);
                macro_rules! run {
                    ($tag_bytes:literal) => {{
                        let tag: [u8; $tag_bytes] = tag.try_into().expect("published tag length");
                        let mut sender = $name::<$tag_bytes>::from_reserved_range(
                            key.as_slice().try_into().expect("fixture key"),
                            &mut schedule,
                            prefix.try_into().expect("prefix"),
                            u64::from_be_bytes(invocation.try_into().expect("counter")),
                            1,
                        )?;
                        let mut dst = vec![0xaa; plain.len()];
                        let result = sender.seal_next(&aad, &plain, &mut dst, &mut work)?;
                        assert_eq!(result, (iv, tag));
                        assert_eq!(dst, ciphertext);
                        assert!(work.iter().all(|b| *b == 0));
                        let mut wrong = tag;
                        wrong[$tag_bytes - 1] ^= 1;
                        work.fill(0x77);
                        assert_eq!(
                            sender.open_in_place(&iv, &aad, &wrong, &mut dst, &mut work),
                            Err(GcmError::Authentication)
                        );
                        assert_eq!(dst, ciphertext);
                        assert!(work.iter().all(|b| *b == 0));
                        sender.open_in_place(&iv, &aad, &tag, &mut dst, &mut work)?;
                        assert_eq!(dst, plain);
                        assert!(work.iter().all(|b| *b == 0));
                    }};
                }
                if seen == 6 {
                    run!(12);
                } else {
                    run!(16);
                }
            }
            assert_eq!(seen, 6);
            Ok(())
        }
    };
}

campaign!(nist_128, Aes128Gcm, "128", 176);
campaign!(nist_192, Aes192Gcm, "192", 208);
campaign!(nist_256, Aes256Gcm, "256", 240);
