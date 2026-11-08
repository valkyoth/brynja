//! Public packaged AES operations retained in a final-linked executable.
#![forbid(unsafe_code)]

use brynja_aes_public_api_fixture::aes::*;
use std::hint::black_box;

fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut result = [0; N];
    for (byte, pair) in result.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    result
}

macro_rules! case {
    ($name:ident, $public:ident, $cached_public:ident, $public_api:ident, $cached_api:ident,
     $key:ident, $cached:ident, $k:literal, $s:literal, $expected:literal) => {
        // Consumer-only observation boundaries. The frozen public fixture and
        // production API remain unchanged; LTO may inline them inside these.
        #[inline(never)]
        fn $public(
            raw: &[u8; $k],
            storage: &mut [u8; $k],
            input: &[u8; 16],
            output: &mut [u8; 16],
        ) -> Result<(), Error> {
            brynja_aes_public_api_fixture::$public_api(raw, storage, input, output)
        }

        #[inline(never)]
        fn $cached_public(
            raw: &[u8; $k],
            storage: &mut [u8; $s],
            input: &[u8; 16],
            output: &mut [u8; 16],
        ) -> Result<(), Error> {
            brynja_aes_public_api_fixture::$cached_api(raw, storage, input, output)
        }

        #[inline(never)]
        fn $name() {
            let mut raw = [0; $k];
            for (byte, value) in raw.iter_mut().zip(0u8..) {
                *byte = value;
            }
            let raw = black_box(raw);
            let input = black_box(hex::<16>("00112233445566778899aabbccddeeff"));
            let cipher = black_box(hex::<16>($expected));
            let mut storage = black_box([0xa5; $k]);
            let mut schedule = black_box([0xa5; $s]);
            let mut output = black_box([0xa5; 16]);
            {
                let owner = $key::new(&raw, &mut storage).unwrap();
                let cached = $cached::new(&raw, &mut schedule).unwrap();
                assert_eq!(
                    owner.encrypt_block(&input, &mut output).unwrap().expose(),
                    cipher
                );
                assert_eq!(output, [0; 16]);
                assert_eq!(
                    owner.decrypt_block(&cipher, &mut output).unwrap().expose(),
                    input
                );
                assert_eq!(output, [0; 16]);
                assert_eq!(
                    cached.encrypt_block(&input, &mut output).unwrap().expose(),
                    cipher
                );
                assert_eq!(output, [0; 16]);
                assert_eq!(
                    cached.decrypt_block(&cipher, &mut output).unwrap().expose(),
                    input
                );
                assert_eq!(output, [0; 16]);
                owner.clear();
                cached.clear();
            }
            assert_eq!(storage, [0; $k]);
            assert_eq!(schedule, [0; $s]);
            $public(&raw, &mut storage, &input, &mut output).unwrap();
            assert_eq!(output, cipher);
            assert_eq!(storage, [0; $k]);
            $cached_public(&raw, &mut schedule, &input, &mut output).unwrap();
            assert_eq!(schedule, [0; $s]);
            assert_eq!(output, cipher);
            println!(
                "AES_LINKED_KAT: {} six operations; secret outputs and key storage cleared",
                $k * 8
            );
        }
    };
}

// FIPS 197 original Appendix C.1/C.2/C.3. No mode API or synthetic AES.
case!(
    aes128,
    public128,
    cached_public128,
    public_block,
    cached_public_block,
    Aes128Key,
    Aes128ExpandedKey,
    16,
    176,
    "69c4e0d86a7b0430d8cdb78070b4c55a"
);
case!(
    aes192,
    public192,
    cached_public192,
    aes192_public,
    aes192_cached_public,
    Aes192Key,
    Aes192ExpandedKey,
    24,
    208,
    "dda97ca4864cdfe06eaf70a0ec0d7191"
);
case!(
    aes256,
    public256,
    cached_public256,
    aes256_public,
    aes256_cached_public,
    Aes256Key,
    Aes256ExpandedKey,
    32,
    240,
    "8ea2b7ca516745bfeafc49904b496089"
);

fn main() {
    aes128();
    aes192();
    aes256();
    println!("AES_LINKED_KAT: complete; 18 operations");
}
