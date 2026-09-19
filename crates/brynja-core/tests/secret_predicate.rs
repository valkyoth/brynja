//! Borrowed predicate validity and non-mutation regression tests.
use brynja_core::secret_byte_mask_is_zero;

#[test]
fn all_byte_mask_predicates_preserve_input() {
    for byte in 0..=u8::MAX {
        for mask in 0..=u8::MAX {
            let region = [0xa5, byte, 0x69];
            assert_eq!(secret_byte_mask_is_zero(&region[1], mask), byte & mask == 0);
            assert_eq!(region, [0xa5, byte, 0x69]);
        }
    }
}

#[test]
fn canonical_masks_disclose_only_validity() {
    for valid in 1..8 {
        let mask = u8::MAX << valid;
        assert!(secret_byte_mask_is_zero(&0, mask));
        assert!(secret_byte_mask_is_zero(&!mask, mask));
        assert!(!secret_byte_mask_is_zero(&u8::MAX, mask));
    }
}
