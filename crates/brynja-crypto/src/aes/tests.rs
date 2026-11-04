extern crate std;
use super::*;
use core::cell::Cell;
use std::{
    boxed::Box,
    panic::{AssertUnwindSafe, catch_unwind, resume_unwind},
};

std::thread_local! {
    static POINT: Cell<usize> = const { Cell::new(0) };
    static FAIL: Cell<Option<(usize,bool)>> = const { Cell::new(None) };
    static CLEARED: Cell<usize> = const { Cell::new(0) };
    static EXPANSION_POINT: Cell<usize> = const { Cell::new(0) };
    static EXPANSION_FAIL: Cell<Option<(usize,bool)>> = const { Cell::new(None) };
}
pub(super) fn expansion_checkpoint() -> Result<(), Error> {
    let point = EXPANSION_POINT.get();
    EXPANSION_POINT.set(point.wrapping_add(1));
    if let Some((selected, unwind)) = EXPANSION_FAIL.get()
        && selected == point
    {
        if unwind {
            resume_unwind(Box::new("AES test-only expansion unwind"));
        }
        return Err(Error::SecretMemory);
    }
    Ok(())
}
pub(super) fn observe_clear(bytes: &[u8]) {
    assert!(bytes.iter().all(|b| *b == 0));
    CLEARED.set(
        CLEARED.get()
            | match bytes.len() {
                176 => 1,
                16 => 2,
                4 => 4,
                _ => 0,
            },
    );
}
pub(super) fn checkpoint() -> Result<(), Error> {
    let point = POINT.get();
    POINT.set(point.wrapping_add(1));
    if let Some((selected, unwind)) = FAIL.get()
        && selected == point
    {
        if unwind {
            resume_unwind(Box::new("AES test-only round unwind"));
        }
        return Err(Error::SecretMemory);
    }
    Ok(())
}

#[test]
fn every_round_failure_and_unwind_clears_output_and_scratch() -> Result<(), Error> {
    for inverse in [false, true] {
        for unwind in [false, true] {
            for point in 0..11 {
                let mut storage = [0; 16];
                let key = Aes128Key::new(&[0x42; 16], &mut storage)?;
                let mut output = [0x99; 16];
                POINT.set(0);
                CLEARED.set(0);
                FAIL.set(Some((point, unwind)));
                let result = catch_unwind(AssertUnwindSafe(|| {
                    key.transform(&[0x77; 16], &mut output, inverse)
                        .map(|b| b.clear())
                }));
                FAIL.set(None);
                if unwind {
                    assert!(result.is_err());
                } else {
                    assert!(matches!(result, Ok(Err(Error::SecretMemory))));
                }
                assert_eq!(output, [0; 16]);
                assert_eq!(CLEARED.get(), 7); // word, state and entire schedule
                // No retained partial schedule or failed-key state.
                key.encrypt_block(&[0; 16], &mut output)?.clear();
                key.clear();
                assert_eq!(storage, [0; 16]);
            }
        }
    }
    Ok(())
}

#[test]
fn public_encryption_failures_preserve_destination_and_clear_scratch() -> Result<(), Error> {
    for unwind in [false, true] {
        for point in 0..11 {
            let mut storage = [0; 16];
            let key = Aes128Key::new(&[0x42; 16], &mut storage)?;
            let input = [0x77; 16];
            let mut output = [0x99; 16];
            POINT.set(0);
            CLEARED.set(0);
            FAIL.set(Some((point, unwind)));
            let result = catch_unwind(AssertUnwindSafe(|| {
                key.encrypt_block_public(&input, &mut output, PublicCiphertext::acknowledge())
            }));
            FAIL.set(None);
            if unwind {
                assert!(result.is_err());
            } else {
                assert!(matches!(result, Ok(Err(Error::SecretMemory))));
            }
            assert_eq!(output, [0x99; 16]);
            assert_eq!(input, [0x77; 16]);
            assert_eq!(CLEARED.get(), 7);
            key.encrypt_block_public(&input, &mut output, PublicCiphertext::acknowledge())?;
            let mut secret = [0; 16];
            assert_eq!(key.encrypt_block(&input, &mut secret)?.expose(), output);
            key.clear();
            assert_eq!(storage, [0; 16]);
        }
    }
    Ok(())
}

#[test]
fn fips197_appendix_a1_complete_schedule() -> Result<(), Error> {
    let mut expected = [0u8; 176];
    let encoded = concat!(
        "2b7e151628aed2a6abf7158809cf4f3c",
        "a0fafe1788542cb123a339392a6c7605",
        "f2c295f27a96b9435935807a7359f67f",
        "3d80477d4716fe3e1e237e446d7a883b",
        "ef44a541a8525b7fb671253bdb0bad00",
        "d4d1c6f87c839d87caf2b8bc11f915bc",
        "6d88a37a110b3efddbf98641ca0093fd",
        "4e54f70e5f5fc9f384a64fb24ea6dc4f",
        "ead27321b58dbad2312bf5607f8d292f",
        "ac7766f319fadc2128d12941575c006e",
        "d014f9a8c9ee2589e13f0cc8b6630ca6"
    );
    for (byte, pair) in expected
        .iter_mut()
        .zip(encoded.as_bytes().as_chunks::<2>().0)
    {
        let pair = core::str::from_utf8(pair).map_err(|_| Error::SecretMemory)?;
        *byte = u8::from_str_radix(pair, 16).map_err(|_| Error::SecretMemory)?;
    }
    let mut schedule = Scratch::<176>::new();
    portable::expand(
        expected.get(..16).ok_or(Error::SecretMemory)?,
        &mut schedule.0,
    )?;
    assert_eq!(schedule.0, expected);
    Ok(())
}

#[test]
fn cached_import_failures_clear_all_storage_and_temporary_schedule() -> Result<(), Error> {
    for unwind in [false, true] {
        // Initial key copy, forty generated words, and caller-schedule write.
        for point in 0..42 {
            let input = [0x42; 16];
            let mut backing = [[0xa5; 176]; 3];
            EXPANSION_POINT.set(0);
            EXPANSION_FAIL.set(Some((point, unwind)));
            CLEARED.set(0);
            let result = catch_unwind(AssertUnwindSafe(|| {
                Aes128ExpandedKey::new(&input, &mut backing[1]).map(|k| k.clear())
            }));
            EXPANSION_FAIL.set(None);
            if unwind {
                assert!(result.is_err());
            } else {
                assert!(matches!(result, Ok(Err(Error::SecretMemory))));
            }
            assert_eq!(backing, [[0xa5; 176], [0; 176], [0xa5; 176]]);
            assert_eq!(input, [0x42; 16]);
            assert_eq!(CLEARED.get() & 5, 5); // expansion word and temporary schedule
            Aes128ExpandedKey::new(&input, &mut backing[1])?.clear();
        }
    }
    Ok(())
}

#[test]
fn cached_round_failures_preserve_key_without_reexpansion() -> Result<(), Error> {
    for public in [false, true] {
        for inverse in [false, true] {
            if public && inverse {
                continue;
            }
            for unwind in [false, true] {
                let mut storage = [0; 176];
                let key = Aes128ExpandedKey::new(&[0x42; 16], &mut storage)?;
                let original = key.region.expose().to_vec();
                EXPANSION_POINT.set(0);
                EXPANSION_FAIL.set(Some((0, false))); // Any per-block expansion must fail.
                for point in 0..11 {
                    let mut output = [0xa5; 16];
                    POINT.set(0);
                    FAIL.set(Some((point, unwind)));
                    CLEARED.set(0);
                    let result = catch_unwind(AssertUnwindSafe(|| {
                        if public {
                            key.encrypt_block_public(
                                &[0x77; 16],
                                &mut output,
                                PublicCiphertext::acknowledge(),
                            )
                        } else {
                            key.transform(&[0x77; 16], &mut output, inverse)
                                .map(|b| b.clear())
                        }
                    }));
                    FAIL.set(None);
                    if unwind {
                        assert!(result.is_err());
                    } else {
                        assert!(matches!(result, Ok(Err(Error::SecretMemory))));
                    }
                    assert_eq!(output, if public { [0xa5; 16] } else { [0; 16] });
                    assert_eq!(key.region.expose(), original);
                    assert_eq!(CLEARED.get(), 2); // state/row scratch only, never a new schedule
                    key.encrypt_block(&[0; 16], &mut output)?.clear();
                }
                assert_eq!(EXPANSION_POINT.get(), 0);
                EXPANSION_FAIL.set(None);
                key.clear();
                assert_eq!(storage, [0; 176]);
            }
        }
    }
    Ok(())
}
