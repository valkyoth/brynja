//! Package-external final-linked accelerated operations, not a benchmark.
#![forbid(unsafe_code)]
use brynja_aes_accelerated_fixture::{aes::*, forced_authority};
use std::hint::black_box;
mod lifecycle;

fn hex<const N: usize>(text: &str) -> [u8; N] {
    assert_eq!(text.len(), N * 2);
    let mut bytes = [0; N];
    for (byte, pair) in bytes.iter_mut().zip(text.as_bytes().as_chunks::<2>().0) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap();
    }
    bytes
}

macro_rules! width {
    ($name:ident, $public:ident, $key:ident, $cached:ident, $k:literal, $s:literal, $expected:literal) => {
        // Retain a package-external operation boundary for final-linked review.
        // Do not change the library's inlining policy to manufacture this body.
        #[inline(never)]
        fn $public(
            key: &$key<'_, '_>,
            input: &[u8; 16],
            output: &mut [u8; 16],
        ) -> Result<(), Error> {
            key.encrypt_block_public(input, output, PublicCiphertext::acknowledge())
        }

        #[inline(never)]
        fn $name() {
            let authority = forced_authority().expect("required acceleration");
            let admitted = authority.get().unwrap();
            let mut raw = [0; $k];
            for (slot, value) in raw.iter_mut().zip(0u8..) {
                *slot = value;
            }
            let raw = black_box(raw);
            let plain = black_box(hex::<16>("00112233445566778899aabbccddeeff"));
            let cipher = black_box(hex::<16>($expected));
            let mut storage = black_box([0xa5; $k]);
            let mut schedule = black_box([0xa5; $s]);
            let mut output = black_box([0xa5; 16]);
            // Exercise both explicit clear and normal Drop through the same
            // opaque package-external lifecycle boundaries, before quarantine.
            for explicit in [false, true] {
                storage.fill(0xa5);
                schedule.fill(0xa5);
                let key = lifecycle::$name::new_key(
                    black_box(admitted),
                    black_box(&raw),
                    black_box(&mut storage),
                )
                .unwrap();
                let cached = lifecycle::$name::new_cached(
                    black_box(admitted),
                    black_box(&raw),
                    black_box(&mut schedule),
                )
                .unwrap();
                lifecycle::$name::destroy_key(black_box(key), black_box(explicit));
                lifecycle::$name::destroy_cached(black_box(cached), black_box(explicit));
                assert_eq!(storage, [0; $k]);
                assert_eq!(schedule, [0; $s]);
            }
            let key = lifecycle::$name::new_key(
                black_box(admitted),
                black_box(&raw),
                black_box(&mut storage),
            )
            .unwrap();
            let cached = lifecycle::$name::new_cached(
                black_box(admitted),
                black_box(&raw),
                black_box(&mut schedule),
            )
            .unwrap();
            let block = key.encrypt_block(&plain, &mut output).unwrap();
            assert_eq!(block.expose(), cipher);
            lifecycle::destroy_block(black_box(block), black_box(false));
            assert_eq!(output, [0; 16]);
            let block = key.decrypt_block(&cipher, &mut output).unwrap();
            assert_eq!(block.expose(), plain);
            lifecycle::destroy_block(black_box(block), black_box(true));
            assert_eq!(output, [0; 16]);
            assert_eq!(
                cached.encrypt_block(&plain, &mut output).unwrap().expose(),
                cipher
            );
            assert_eq!(output, [0; 16]);
            assert_eq!(
                cached.decrypt_block(&cipher, &mut output).unwrap().expose(),
                plain
            );
            assert_eq!(output, [0; 16]);
            $public(black_box(&key), black_box(&plain), black_box(&mut output)).unwrap();
            assert_eq!(output, cipher);
            cached
                .encrypt_block_public(&plain, &mut output, PublicCiphertext::acknowledge())
                .unwrap();
            assert_eq!(output, cipher);
            admitted.quarantine();
            assert!(key.encrypt_block(&plain, &mut output).is_err());
            assert_eq!(output, [0; 16]);
            output.fill(0xa5);
            assert!(key.decrypt_block(&cipher, &mut output).is_err());
            assert_eq!(output, [0; 16]);
            output.fill(0xa5);
            assert!(cached.encrypt_block(&plain, &mut output).is_err());
            assert_eq!(output, [0; 16]);
            output.fill(0xa5);
            assert!(cached.decrypt_block(&cipher, &mut output).is_err());
            assert_eq!(output, [0; 16]);
            output.fill(0xa5);
            assert!(
                cached
                    .encrypt_block_public(&plain, &mut output, PublicCiphertext::acknowledge())
                    .is_err()
            );
            assert_eq!(output, [0xa5; 16]);
            assert!($public(black_box(&key), black_box(&plain), black_box(&mut output)).is_err());
            assert_eq!(output, [0xa5; 16]);
            lifecycle::$name::destroy_key(black_box(key), black_box(true));
            lifecycle::$name::destroy_cached(black_box(cached), black_box(true));
            assert_eq!(storage, [0; $k]);
            assert_eq!(schedule, [0; $s]);
            storage.fill(0xa5);
            schedule.fill(0xa5);
            assert!(
                lifecycle::$name::new_key(
                    black_box(admitted),
                    black_box(&raw),
                    black_box(&mut storage)
                )
                .is_err()
            );
            assert!(
                lifecycle::$name::new_cached(
                    black_box(admitted),
                    black_box(&raw),
                    black_box(&mut schedule)
                )
                .is_err()
            );
            assert_eq!(storage, [0; $k]);
            assert_eq!(schedule, [0; $s]);
            println!(
                "AES_ACCELERATED_LINKED_KAT: {}; six operations; clearing and quarantine checked",
                $k * 8
            );
        }
    };
}

width!(
    aes128,
    public128,
    Aes128Key,
    Aes128ExpandedKey,
    16,
    176,
    "69c4e0d86a7b0430d8cdb78070b4c55a"
);
width!(
    aes192,
    public192,
    Aes192Key,
    Aes192ExpandedKey,
    24,
    208,
    "dda97ca4864cdfe06eaf70a0ec0d7191"
);
width!(
    aes256,
    public256,
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
}
