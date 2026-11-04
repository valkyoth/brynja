//! Downstream observations using public types only; no production source includes.
#![forbid(unsafe_code)]
use brynja_aes_public_api_fixture::{
    aes::{Aes128ExpandedKey, Aes128Key},
    cached_public_block, public_block,
};

// FIPS 197 original Appendix C.1; independently frozen expected block.
const KEY: [u8; 16] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
const INPUT: [u8; 16] = [
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
];
const CIPHER: [u8; 16] = [
    0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30, 0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
];

#[test]
fn known_answer_both_directions() {
    let mut storage = [0xa5; 16];
    let key = Aes128Key::new(&KEY, &mut storage).unwrap();
    let mut ciphertext = [0xa5; 16];
    let encrypted = key.encrypt_block(&INPUT, &mut ciphertext).unwrap();
    assert_eq!(encrypted.expose(), CIPHER);
    let mut plaintext = [0xa5; 16];
    let decrypted = key.decrypt_block(&CIPHER, &mut plaintext).unwrap();
    assert_eq!(decrypted.expose(), INPUT);
    let mut expanded = [0; 176];
    let cached = Aes128ExpandedKey::new(&KEY, &mut expanded).unwrap();
    let mut block = [0; 16];
    assert_eq!(
        cached.encrypt_block(&INPUT, &mut block).unwrap().expose(),
        CIPHER
    );
    assert_eq!(
        cached.decrypt_block(&CIPHER, &mut block).unwrap().expose(),
        INPUT
    );
}

#[test]
fn drop_clears_only_owned_regions() {
    let mut keys = [[0xa5; 16]; 3];
    let mut outputs = [[0x5a; 16]; 3];
    {
        let key = Aes128Key::new(&KEY, &mut keys[1]).unwrap();
        let output = key.encrypt_block(&INPUT, &mut outputs[1]).unwrap();
        assert_eq!(output.expose(), CIPHER);
    }
    assert_eq!(keys, [[0xa5; 16], [0; 16], [0xa5; 16]]);
    assert_eq!(outputs, [[0x5a; 16], [0; 16], [0x5a; 16]]);
    let mut schedules = [[0xa5; 176]; 3];
    {
        let cached = Aes128ExpandedKey::new(&KEY, &mut schedules[1]).unwrap();
        let output = cached.encrypt_block(&INPUT, &mut outputs[1]).unwrap();
        assert_eq!(output.expose(), CIPHER);
    }
    assert_eq!(schedules, [[0xa5; 176], [0; 176], [0xa5; 176]]);
    assert_eq!(outputs, [[0x5a; 16], [0; 16], [0x5a; 16]]);
}

#[test]
fn explicit_clear_and_reuse() {
    let mut storage = [0xa5; 16];
    let mut output = [0x5a; 16];
    for _ in 0..4 {
        let key = Aes128Key::new(&KEY, &mut storage).unwrap();
        let block = key.decrypt_block(&CIPHER, &mut output).unwrap();
        assert_eq!(block.expose(), INPUT);
        block.clear();
        key.clear();
        assert_eq!(output, [0; 16]);
        assert_eq!(storage, [0; 16]);
    }
    let mut expanded = [0xa5; 176];
    let cached = Aes128ExpandedKey::new(&KEY, &mut expanded).unwrap();
    for _ in 0..4 {
        cached.decrypt_block(&CIPHER, &mut output).unwrap().clear();
    }
    cached.clear();
    assert_eq!(expanded, [0; 176]);
    assert_eq!(output, [0; 16]);
}

#[test]
fn output_outlives_key() {
    let mut storage = [0xa5; 16];
    let mut destination = [0x5a; 16];
    let output = {
        let key = Aes128Key::new(&KEY, &mut storage).unwrap();
        key.encrypt_block(&INPUT, &mut destination).unwrap()
    };
    assert_eq!(storage, [0; 16]);
    assert_eq!(output.expose(), CIPHER);
    output.clear();
    assert_eq!(destination, [0; 16]);
    let mut expanded = [0; 176];
    let output = {
        let cached = Aes128ExpandedKey::new(&KEY, &mut expanded).unwrap();
        cached.encrypt_block(&INPUT, &mut destination).unwrap()
    };
    assert_eq!(expanded, [0; 176]);
    assert_eq!(output.expose(), CIPHER);
    output.clear();
}

#[test]
fn public_ciphertext_persists_after_key_clear() {
    let mut storage = [0xa5; 16];
    let mut destination = [0x5a; 16];
    public_block(&KEY, &mut storage, &INPUT, &mut destination).unwrap();
    assert_eq!(destination, CIPHER);
    assert_eq!(storage, [0; 16]);
    assert_eq!(KEY[15], 15); // Caller copies remain caller-owned.
    let mut expanded = [0; 176];
    cached_public_block(&KEY, &mut expanded, &INPUT, &mut destination).unwrap();
    assert_eq!(destination, CIPHER);
    assert_eq!(expanded, [0; 176]);
}

#[test]
fn consumer_unwind_clears_key_and_output() {
    let mut storage = [0xa5; 16];
    let mut destination = [0x5a; 16];
    let mut reached_caller_panic = false;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let key = Aes128Key::new(&KEY, &mut storage).unwrap();
        let output = key.encrypt_block(&INPUT, &mut destination).unwrap();
        assert_eq!(output.expose(), CIPHER);
        reached_caller_panic = true;
        panic!("intentional downstream unwind");
    }));
    assert!(result.is_err());
    assert!(reached_caller_panic);
    assert_eq!(storage, [0; 16]);
    assert_eq!(destination, [0; 16]);
    let mut expanded = [0xa5; 176];
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let cached = Aes128ExpandedKey::new(&KEY, &mut expanded).unwrap();
        let block = cached.encrypt_block(&INPUT, &mut destination).unwrap();
        assert_eq!(block.expose(), CIPHER);
        panic!("intentional cached-owner unwind");
    }));
    assert!(result.is_err());
    assert_eq!(expanded, [0; 176]);
    assert_eq!(destination, [0; 16]);
}
