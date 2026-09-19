extern crate std;
use super::*;
use std::vec::Vec;

fn mask(bits: u8) -> u8 {
    u8::MAX
        .checked_shr(u32::from(8_u8.saturating_sub(bits)))
        .unwrap_or(0)
}

#[test]
fn borrowed_prefix_fragments_cover_every_byte_offset_and_width() -> Result<(), ()> {
    for offset in 0_u8..8 {
        for valid in 1_u8..=8 {
            for source in 0..=u8::MAX {
                let mut actual = Vec::new();
                let mut sink = |bytes: &[u8]| {
                    actual.extend_from_slice(bytes);
                    Ok(())
                };
                let mut pending = [0xa5];
                {
                    let mut packer = PrefixPacker::new(&mut sink, &mut pending);
                    if offset != 0 {
                        packer.push_bits(&0x55, offset)?;
                    }
                    packer.push_bits(&source, valid)?;
                    packer.finish(1)?;
                    assert_eq!(*packer.pending, [0]);
                    assert_eq!(packer.used, 0);
                    assert_eq!(
                        packer.emitted,
                        usize::from(offset.checked_add(valid).ok_or(())?).div_ceil(8)
                    );
                }
                let combined =
                    u16::from(0x55 & mask(offset)) | (u16::from(source & mask(valid)) << offset);
                let expected = combined.to_le_bytes();
                let count = usize::from(offset.checked_add(valid).ok_or(())?).div_ceil(8);
                assert_eq!(actual.as_slice(), expected.get(..count).ok_or(())?);
                assert_eq!(pending, [0]);
            }
        }
    }
    Ok(())
}

#[test]
fn borrowed_prefix_keeps_bulk_and_unaligned_byte_paths() -> Result<(), ()> {
    let bytes = [0x96; 4096];
    let mut lengths = Vec::new();
    let mut sink = |input: &[u8]| {
        lengths.push(input.len());
        assert_eq!(input, bytes);
        Ok(())
    };
    let mut pending = [0xa5];
    {
        let mut packer = PrefixPacker::new(&mut sink, &mut pending);
        packer.push_bytes(&bytes)?;
        assert_eq!(packer.emitted, bytes.len());
    }
    assert_eq!(lengths, [4096]);
    assert_eq!(pending, [0]);
    for offset in 1..8 {
        let mut actual = Vec::new();
        let mut sink = |input: &[u8]| {
            actual.extend_from_slice(input);
            Ok(())
        };
        let mut pending = [0xa5];
        {
            let mut packer = PrefixPacker::new(&mut sink, &mut pending);
            packer.push_bits(&0x55, offset)?;
            packer.push_bytes(&bytes[..273])?;
            packer.push_bits(&0x07, 3)?;
            packer.finish(168)?;
        }
        let mut bits = Vec::new();
        append_bits(&mut bits, &[0x55], usize::from(offset));
        append_bits(&mut bits, &bytes[..273], 273 * 8);
        append_bits(&mut bits, &[0x07], 3);
        while bits.len() % (168 * 8) != 0 {
            bits.push(0);
        }
        assert_eq!(actual, encode_bits(&bits));
        assert_eq!(pending, [0]);
    }
    Ok(())
}

fn append_bits(output: &mut Vec<u8>, input: &[u8], bits: usize) {
    output.extend(
        input
            .iter()
            .flat_map(|byte| (0..8).map(move |bit| (byte >> bit) & 1))
            .take(bits),
    );
}

fn encode_bits(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8)
        .map(|chunk| {
            chunk
                .iter()
                .enumerate()
                .fold(0, |value, (position, bit)| value | (bit << position))
        })
        .collect()
}

#[test]
fn borrowed_prefix_failures_clear_scratch_and_preflight_counters() -> Result<(), ()> {
    let mut calls = 0_usize;
    let mut sink = |_: &[u8]| {
        calls = calls.checked_add(1).ok_or(())?;
        Ok(())
    };
    let mut pending = [0xa5];
    {
        let mut packer = PrefixPacker::new(&mut sink, &mut pending);
        packer.emitted = usize::MAX;
        assert_eq!(packer.push_bytes(&[0x96]), Err(()));
        assert_eq!(packer.flush(), Err(()));
        assert_eq!(packer.finish(2), Err(()));
        assert_eq!(packer.emitted, usize::MAX);
        for used in [0, 7, 8, 255] {
            for valid in [0, 9, 255] {
                packer.used = used;
                packer.pending[0] = 0x69;
                assert_eq!(packer.push_bits(&0x96, valid), Err(()));
                assert_eq!(*packer.pending, [0x69]);
                assert_eq!(packer.used, used);
            }
            if used >= 8 {
                assert_eq!(packer.push_bits(&0x96, 8), Err(()));
                assert_eq!(*packer.pending, [0x69]);
                assert_eq!(packer.used, used);
            }
        }
    }
    assert_eq!(calls, 0);
    assert_eq!(pending, [0]);
    for panic in [false, true] {
        let mut pending = [0xa5];
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut sink = |_: &[u8]| {
                assert!(!panic, "prefix test unwind");
                Err(())
            };
            let mut packer = PrefixPacker::new(&mut sink, &mut pending);
            packer.push_bits(&0x55, 7)?;
            packer.push_bits(&0x03, 2)
        }));
        if panic {
            assert!(result.is_err());
        } else {
            assert_eq!(result.ok(), Some(Err(())));
        }
        assert_eq!(pending, [0]);
    }
    Ok(())
}

fn reference_left(bits: &mut Vec<u8>, value: usize) -> Result<(), ()> {
    let bytes = value.to_be_bytes();
    let start = bytes
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(bytes.len().saturating_sub(1));
    let body = bytes.get(start..).ok_or(())?;
    append_bits(bits, &[u8::try_from(body.len()).map_err(|_| ())?], 8);
    append_bits(bits, body, body.len().checked_mul(8).ok_or(())?);
    Ok(())
}

#[test]
fn borrowed_cshake_prefix_matches_bit_concatenation() -> Result<(), ()> {
    for rate in [136_usize, 168] {
        let lengths = [
            0,
            1,
            7,
            8,
            9,
            rate.checked_mul(8)
                .and_then(|n| n.checked_sub(1))
                .ok_or(())?,
            rate.checked_mul(8)
                .and_then(|n| n.checked_add(3))
                .ok_or(())?,
        ];
        for n in lengths {
            for s in lengths {
                let mut name = std::vec![0x96; n.div_ceil(8)];
                let mut custom = std::vec![0x69; s.div_ceil(8)];
                let name_bits = canonical(&mut name, n)?;
                let custom_bits = canonical(&mut custom, s)?;
                let mut actual = Vec::new();
                let customized = absorb_cshake_prefix(rate, name_bits, custom_bits, |bytes| {
                    actual.extend_from_slice(bytes);
                    Ok(())
                })?;
                assert_eq!(customized, n != 0 || s != 0);
                let mut expected = Vec::new();
                if customized {
                    reference_left(&mut expected, rate)?;
                    reference_left(&mut expected, n)?;
                    append_bits(&mut expected, &name, n);
                    reference_left(&mut expected, s)?;
                    append_bits(&mut expected, &custom, s);
                    let boundary = rate.checked_mul(8).ok_or(())?;
                    while expected.len() % boundary != 0 {
                        expected.push(0);
                    }
                }
                assert_eq!(
                    actual,
                    encode_bits(&expected),
                    "rate={rate} name={n} customization={s}"
                );
            }
        }
    }
    Ok(())
}

fn canonical(bytes: &mut [u8], bits: usize) -> Result<Fips202BitString<'_>, ()> {
    let valid = if bits == 0 {
        0
    } else if bits.is_multiple_of(8) {
        8
    } else {
        u8::try_from(bits % 8).map_err(|_| ())?
    };
    if let Some(byte) = bytes.last_mut() {
        *byte &= mask(valid);
    }
    Fips202BitString::new(bytes, valid).map_err(|_| ())
}
