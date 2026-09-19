extern crate std;

use super::*;

struct Sink {
    fail: bool,
    unwind: bool,
}
impl Absorb for Sink {
    fn absorb(&mut self, _: &[u8]) -> Result<(), KmacError> {
        if self.unwind {
            std::panic::resume_unwind(std::boxed::Box::new(()));
        }
        if self.fail {
            Err(KmacError::StateConsumed)
        } else {
            Ok(())
        }
    }
}

fn cleared(frame: &Framing) -> bool {
    frame.pending == [0] && frame.used == [0] && frame.emitted.iter().all(|byte| *byte == 0)
}

#[test]
fn encoded_integer_initializes_in_place_and_clears_reused_storage() -> Result<(), KmacError> {
    let mut encoding = SecretEncodedInteger::new();
    let address = encoding.bytes.as_ptr();
    for bits in 0..128 {
        for value in [0, 1_u128 << bits, (1_u128 << bits) - 1, u128::MAX] {
            encoding.left_encode(value)?;
            assert_eq!(encoding.bytes.as_ptr(), address);
            assert_eq!(encoding.as_bytes()?, left_encode_u128(value).as_bytes());
            assert!(
                encoding
                    .bytes
                    .get(encoding.as_bytes()?.len()..)
                    .ok_or(KmacError::SecretMemory)?
                    .iter()
                    .all(|byte| *byte == 0)
            );
        }
    }
    encoding.wipe();
    assert_eq!(encoding.bytes, [0; 17]);
    assert_eq!(encoding.length, [0]);
    Ok(())
}

#[test]
fn partial_tail_borrows_final_frame_and_cleanup_covers_every_exit() -> Result<(), KmacError> {
    for valid in 1..=8 {
        for exit in 0..7 {
            let mut storage = Framing::new();
            let address = storage.pending.as_ptr();
            let mut sink = Sink {
                fail: false,
                unwind: false,
            };
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut packer = SecretPacker::new(&mut sink, &mut storage);
                packer.push_bits(&0xff, valid)?;
                if exit == 2 {
                    packer.state.fail = true;
                }
                if exit == 3 {
                    packer.state.unwind = true;
                }
                if exit == 4 {
                    packer.storage.emitted = usize::MAX.to_le_bytes();
                }
                if exit == 5 {
                    return packer.finish_bytepad(0);
                }
                if exit == 6 {
                    packer.storage.used = [9];
                    return packer.finish_bits(|_, _| Ok(()));
                }
                packer.push_bytes(&[0xff; 17])?;
                packer.finish_bits(|_, tail| {
                    if valid == 8 {
                        assert!(tail.as_bytes().is_empty());
                    } else {
                        assert_eq!(tail.as_bytes().as_ptr(), address);
                        assert_eq!(tail.valid_bits_in_last_byte(), valid);
                    }
                    if exit == 0 {
                        Ok(())
                    } else {
                        Err(KmacError::StateConsumed)
                    }
                })
            }));
            if exit == 3 {
                assert!(result.is_err());
            } else {
                assert_eq!(
                    result.map_err(|_| KmacError::SecretMemory)?.is_ok(),
                    exit == 0
                );
            }
            assert!(cleared(&storage));
            sink.fail = false;
            sink.unwind = false;
            let mut packer = SecretPacker::new(&mut sink, &mut storage);
            packer.push_bits(&0x5, 3)?;
            let unwind = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let mut packer = packer;
                packer.finish_bits::<()>(|_, _| std::panic::resume_unwind(std::boxed::Box::new(())))
            }));
            assert!(unwind.is_err());
            assert!(cleared(&storage));
        }
    }
    Ok(())
}

#[test]
fn bytepad_retains_frame_and_clears_on_guard_drop() -> Result<(), KmacError> {
    let mut sink = Sink {
        fail: false,
        unwind: false,
    };
    let mut storage = Framing::new();
    let address = core::ptr::from_ref(&storage);
    {
        let mut packer = SecretPacker::new(&mut sink, &mut storage);
        packer.push_bits(&0x5, 3)?;
        packer.finish_bytepad(168)?;
        assert_eq!(core::ptr::from_ref(&*packer.storage), address);
        assert_eq!(packer.emitted(), 168);
    }
    assert!(cleared(&storage));
    Ok(())
}

#[derive(Default)]
struct RecordingSink(std::vec::Vec<u8>);

impl Absorb for RecordingSink {
    fn absorb(&mut self, input: &[u8]) -> Result<(), KmacError> {
        self.0.extend_from_slice(input);
        Ok(())
    }
}

#[test]
fn borrowed_fragments_match_bit_oracle_at_every_alignment() -> Result<(), KmacError> {
    for used in 0..8 {
        for valid in 0..=8 {
            for value in 0..=u8::MAX {
                let mut sink = RecordingSink::default();
                let mut frame = Framing::new();
                let mut reference = std::vec::Vec::<u8>::new();
                let mut bits = 0_usize;
                // Independent bit-at-a-time model, including carried bytes.
                for (byte, width) in [(0xa5, used), (value, valid), (0x96, 8), (0x69, 8)] {
                    for position in 0..width {
                        if bits.is_multiple_of(8) {
                            reference.push(0);
                        }
                        if let Some(last) = reference.last_mut() {
                            *last |= ((byte >> position) & 1) << (bits % 8);
                        }
                        bits += 1;
                    }
                }
                {
                    let mut packer = SecretPacker::new(&mut sink, &mut frame);
                    packer.push_bits(&0xa5, used)?;
                    packer.push_bits(&value, valid)?;
                    packer.push_bytes(&[0x96, 0x69])?;
                    assert_eq!(packer.emitted(), bits / 8);
                    assert_eq!(usize::from(packer.used()), bits % 8);
                    assert_eq!(
                        packer.state.0,
                        reference.get(..bits / 8).ok_or(KmacError::SecretMemory)?
                    );
                    let tail = if bits.is_multiple_of(8) {
                        0
                    } else {
                        *reference.get(bits / 8).ok_or(KmacError::SecretMemory)?
                    };
                    assert_eq!(packer.storage.pending, [tail]);
                }
                assert!(cleared(&frame));
            }
        }
    }
    Ok(())
}

#[test]
fn invalid_fragment_shape_rejects_before_absorption_and_clears() -> Result<(), KmacError> {
    for (used, valid) in [(8, 0), (8, 1), (9, 8), (255, 8), (0, 9), (3, 255)] {
        let mut sink = RecordingSink::default();
        let mut frame = Framing::new();
        {
            let mut packer = SecretPacker::new(&mut sink, &mut frame);
            packer.storage.pending = [0xa5];
            packer.storage.used = [used];
            assert_eq!(
                packer.push_bits(&0x96, valid),
                Err(KmacError::InvalidBitString)
            );
            assert_eq!(packer.storage.pending, [0xa5]);
            assert_eq!(packer.storage.used, [used]);
            assert!(packer.state.0.is_empty());
        }
        assert!(cleared(&frame));
    }
    Ok(())
}
