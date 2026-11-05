//! Bounded field/index proofs, not full AES, cleanup or constant-time proofs.
#![no_std]
#![forbid(unsafe_code)]
#![allow(dead_code)]

// Direct production source, not a copied or stubbed implementation.
#[path = "../../../crates/brynja-crypto/src/aes/portable/field.rs"]
mod field;
#[path = "../../../crates/brynja-crypto/src/aes/portable/layout.rs"]
mod layout;

#[cfg(kani)]
mod proofs {
    use super::*;

    #[kani::proof]
    #[kani::unwind(9)]
    fn multiplication_matches_polynomial_reduction() {
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        // Independent schoolbook carryless product in a wider integer, then
        // long division by the FIPS 197 modulus, not the masked xtime loop.
        let mut product = 0u16;
        for bit in 0..8 {
            if (b >> bit) & 1 != 0 {
                product ^= u16::from(a) << bit;
            }
        }
        for degree in (8..16).rev() {
            if (product >> degree) & 1 != 0 {
                product ^= 0x11bu16 << (degree - 8);
            }
        }
        assert_eq!(u16::from(field::multiply(a, b)), product);
    }

    #[kani::proof]
    fn shift_indices_are_bounded_inverse_permutations() {
        let index: usize = kani::any();
        let other: usize = kani::any();
        let inverse: bool = kani::any();
        kani::assume(index < 16 && other < 16);
        let source = layout::shift_source(index, inverse);
        assert!(source < 16);
        assert_eq!(source % 4, index % 4);
        assert_eq!(layout::shift_source(source, !inverse), index);
        assert_eq!(
            source == layout::shift_source(other, inverse),
            index == other
        );
    }

    #[kani::proof]
    fn admitted_round_key_indices_are_exact_and_bounded() {
        let width: u8 = kani::any();
        kani::assume(width < 3);
        let (rounds, size) = match width {
            0 => (10, 176),
            1 => (12, 208),
            _ => (14, 240),
        };
        let round: usize = kani::any();
        let byte: usize = kani::any();
        kani::assume(round <= rounds && byte < 16);
        let index = layout::round_key_index(round, byte);
        assert_eq!(index, round * 16 + byte);
        assert!(index < size);
        assert_eq!(index / 16, round);
        assert_eq!(index % 16, byte);
    }

    #[kani::proof]
    fn wide_parameter_admission_is_exact() {
        let key: usize = kani::any();
        let size: usize = kani::any();
        let rounds: usize = kani::any();
        let admitted = layout::valid_wide_parameters(key, size, rounds);
        assert_eq!(
            admitted,
            (key == 24 && size == 208 && rounds == 12)
                || (key == 32 && size == 240 && rounds == 14)
        );
        if admitted {
            assert_eq!(size, (rounds + 1) * 16);
            assert_eq!(rounds, key / 4 + 6);
            assert!(key < size);
        }
    }

    #[kani::proof]
    fn wide_schedule_indices_reference_initialized_words() {
        let aes256: bool = kani::any();
        let (key, size) = if aes256 { (32, 240) } else { (24, 208) };
        let offset: usize = kani::any();
        let byte: usize = kani::any();
        kani::assume(offset >= key && offset < size && offset % 4 == 0 && byte < 4);
        let destination = layout::word_byte_index(offset, byte);
        let previous = layout::prior_word_index(offset, 4, byte);
        let prior = layout::prior_word_index(offset, key, byte);
        assert_eq!(destination, offset + byte);
        assert_eq!(previous, offset - 4 + byte);
        assert_eq!(prior, offset - key + byte);
        assert!(destination < size);
        assert!(previous < offset && prior < offset);
        assert_eq!(previous % 4, byte);
        assert_eq!(prior % 4, byte);
        assert_eq!(destination % 4, byte);
    }
}
