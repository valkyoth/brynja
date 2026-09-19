use crate::{accumulate_secret_byte_difference as accumulate, secret_difference_is_zero};

#[test]
fn borrowed_difference_byte_pairs_and_sticky_bits() {
    for left in 0..=u8::MAX {
        for right in 0..=u8::MAX {
            for initial in [0, 1, 0x80, 0xff] {
                let mut region = [0xa5, initial, 0x69];
                accumulate(&mut region[1], &left, &right);
                assert_eq!(region, [0xa5, initial | (left ^ right), 0x69]);
                assert_eq!(
                    secret_difference_is_zero(&region[1]).expose_public(),
                    initial == 0 && left == right
                );
            }
        }
    }
}

#[test]
fn borrowed_difference_alias_and_repeated_mismatches() {
    for byte in 0..=u8::MAX {
        let mut difference = 0;
        accumulate(&mut difference, &byte, &byte);
        assert!(secret_difference_is_zero(&difference).expose_public());
        accumulate(&mut difference, &byte, &(byte ^ 0x80));
        accumulate(&mut difference, &byte, &(byte ^ 0x80));
        accumulate(&mut difference, &byte, &byte);
        assert_eq!(difference, 0x80);
        assert!(!secret_difference_is_zero(&difference).expose_public());
    }
}
