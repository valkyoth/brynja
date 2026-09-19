use crate::{SecretBitRangeError, xor_secret_byte_bits};

#[test]
fn bit_ranges_are_checked_before_mutation() {
    for right in (0..=9).chain([255]) {
        for count in (0..=9).chain([255]) {
            for left in (0..=9).chain([255]) {
                let mut out = [0xa5, 0x69, 0x3c];
                let source = 0x96;
                let result = xor_secret_byte_bits(&mut out[1], &source, right, count, left);
                if (1..=8).contains(&count) && right <= 8 - count && left <= 8 - count {
                    assert_eq!(result, Ok(()));
                    let mask = (1_u16 << count) - 1;
                    let expected =
                        u8::try_from(((u16::from(source) >> right) & mask) << left).unwrap_or(0);
                    assert_eq!(out, [0xa5, 0x69 ^ expected, 0x3c]);
                } else {
                    assert_eq!(result, Err(SecretBitRangeError));
                    assert_eq!(out, [0xa5, 0x69, 0x3c]);
                }
                assert_eq!(source, 0x96);
            }
        }
    }
}
