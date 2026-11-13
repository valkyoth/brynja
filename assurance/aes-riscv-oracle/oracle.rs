//! Host-generated OpenSSL answers replayed through forced RV64 owners.
//! Public synthetic inputs; no oracle process is launched inside QEMU.
#![forbid(unsafe_code)]

use brynja_aes_accelerated_fixture::{aes::*, forced_authority};
type Check<T> = Result<T, Box<dyn std::error::Error>>;
const CASES: usize = 2048;

fn records<const N: usize>(bytes: &[u8]) -> Check<&[[u8; N]]> {
    let (rows, tail) = bytes.as_chunks::<N>();
    if rows.len() != CASES || !tail.is_empty() {
        return Err("oracle corpus population/record size mismatch".into());
    }
    Ok(rows)
}

#[test]
fn malformed_population_is_rejected() {
    let valid = vec![0_u8; CASES * 64];
    assert!(records::<64>(&valid).is_ok());
    assert!(records::<64>(&valid[..valid.len() - 1]).is_err());
    assert!(records::<64>(&valid[..valid.len() - 64]).is_err());
    assert!(records::<64>(&vec![0_u8; valid.len() + 1]).is_err());
    assert!(records::<64>(&vec![0_u8; valid.len() + 64]).is_err());
}

macro_rules! width {
    ($test:ident, $key:ident, $cached:ident, $k:literal, $s:literal, $bits:literal) => {
        #[test]
        fn $test() -> Check<()> {
            let authority = forced_authority()?;
            let corpus = include_bytes!(concat!("fixtures/oracle", $bits, ".bin"));
            let rows = records::<{ $k + 48 }>(corpus)?;
            let mut count = 0_usize;
            for record in rows {
                let (key_bytes, rest) = record.split_at($k);
                let key_bytes: &[u8; $k] = key_bytes.try_into()?;
                let (input, answers) = rest.split_at(16);
                let input: &[u8; 16] = input.try_into()?;
                let (encrypted, decrypted) = answers.split_at(16);
                let mut storage = [0xa5; $k];
                let mut schedule = [0xa5; $s];
                let key = $key::new(authority.get()?, key_bytes, &mut storage)
                    .map_err(|e| format!("{e:?}"))?;
                let cached = $cached::new(authority.get()?, key_bytes, &mut schedule)
                    .map_err(|e| format!("{e:?}"))?;
                for cache in [false, true] {
                    for (inverse, expected) in [(false, encrypted), (true, decrypted)] {
                        let mut output = [0xa5; 16];
                        let block = match (cache, inverse) {
                            (false, false) => key.encrypt_block(input, &mut output),
                            (false, true) => key.decrypt_block(input, &mut output),
                            (true, false) => cached.encrypt_block(input, &mut output),
                            (true, true) => cached.decrypt_block(input, &mut output),
                        }.map_err(|e| format!("{e:?}"))?;
                        assert_eq!(block.expose(), expected, "case {count}, inverse={inverse}, cached={cache}");
                        block.clear();
                        assert_eq!(output, [0; 16]);
                    }
                    let mut output = [0xa5; 16];
                    if cache {
                        cached.encrypt_block_public(input, &mut output, PublicCiphertext::acknowledge())
                    } else {
                        key.encrypt_block_public(input, &mut output, PublicCiphertext::acknowledge())
                    }.map_err(|e| format!("{e:?}"))?;
                    assert_eq!(output, encrypted, "public case {count}, cached={cache}");
                }
                key.clear();
                cached.clear();
                assert_eq!(storage, [0; $k]);
                assert_eq!(schedule, [0; $s]);
                count += 1;
            }
            assert_eq!(count, CASES);
            println!("AES_RISCV_ORACLE: {} 2048 inputs; independent encrypt/decrypt; both owners; public output", $bits);
            Ok(())
        }
    };
}

width!(aes128_oracle, Aes128Key, Aes128ExpandedKey, 16, 176, 128);
width!(aes192_oracle, Aes192Key, Aes192ExpandedKey, 24, 208, 192);
width!(aes256_oracle, Aes256Key, Aes256ExpandedKey, 32, 240, 256);
