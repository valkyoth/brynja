//! Public fixtures only. Functional substitution tests, not fault qualification.
use super::*;

// FIPS 197-upd1 Table 4, row-major byte order (not primary arithmetic output).
// https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197-upd1.pdf
const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn inverse_fixture() -> Result<[u8; 256], Error> {
    let mut result = [0; 256];
    for (value, cell) in result.iter_mut().enumerate() {
        let source = SBOX
            .iter()
            .position(|v| usize::from(*v) == value)
            .ok_or(Error::SecretMemory)?;
        *cell = u8::try_from(source).map_err(|_| Error::SecretMemory)?;
    }
    Ok(result)
}

#[test]
fn coefficients_reconstruct_from_fips_by_subset_parity() -> Result<(), Error> {
    let inverse = inverse_fixture()?;
    for (table, coefficients) in [
        (&SBOX, &coefficients::FORWARD),
        (&inverse, &coefficients::INVERSE),
    ] {
        // Direct subset parity, not the generator's in-place Mobius transform.
        for (mask, expected) in coefficients.iter().enumerate() {
            let mut coefficient = 0;
            for (subset, value) in table.iter().enumerate() {
                if subset & mask == subset {
                    coefficient ^= value;
                }
            }
            assert_eq!(coefficient, *expected, "monomial {mask}");
        }
    }
    Ok(())
}

#[test]
fn representation_is_exact_for_every_byte_in_every_lane() -> Result<(), Error> {
    let mut planes = Planes::new();
    for lane in 0..16 {
        for value in 0..=u8::MAX {
            let mut input = [0; 16];
            *input.get_mut(lane).ok_or(Error::SecretMemory)? = value;
            planes.load(&input)?;
            // Check the representation itself, not just mutually inverse codecs.
            for (position, plane) in planes.0.0.iter().enumerate() {
                let expected = if position / 8 == lane / 8 {
                    ((value >> (position % 8)) & 1) << (lane % 8)
                } else {
                    0
                };
                assert_eq!(*plane, expected);
            }
            let mut output = [0xff; 16];
            planes.store(&mut output)?;
            assert_eq!(output, input);
        }
    }
    // Reuse must replace, not accumulate, previously loaded bits.
    planes.load(&[0xff; 16])?;
    planes.load(&[0; 16])?;
    assert_eq!(planes.0.0, [0; 16]);
    Ok(())
}

#[test]
fn all_values_in_each_lane_match_fips_with_distinct_neighbors() -> Result<(), Error> {
    let inverse_table = inverse_fixture()?;
    for inverse in [false, true] {
        let table = if inverse { &inverse_table } else { &SBOX };
        for lane in 0..16 {
            for value in 0..=u8::MAX {
                let mut input = [0; 16];
                for (index, byte) in input.iter_mut().enumerate() {
                    *byte = u8::try_from(index)
                        .map_err(|_| Error::SecretMemory)?
                        .wrapping_mul(17)
                        .wrapping_add(value);
                }
                *input.get_mut(lane).ok_or(Error::SecretMemory)? = value;
                let mut planes = Planes::new();
                planes.load(&input)?;
                planes.substitute(inverse)?;
                let mut output = [0; 16];
                planes.store(&mut output)?;
                for (actual, original) in output.iter().zip(input) {
                    assert_eq!(
                        *actual,
                        read(table, usize::from(original))?,
                        "direction {inverse}, lane {lane}, value {value}"
                    );
                }
            }
        }
    }
    Ok(())
}

#[test]
fn replicated_bytes_and_round_trips_match_both_tables() -> Result<(), Error> {
    let inverse_table = inverse_fixture()?;
    for value in 0..=u8::MAX {
        for inverse in [false, true] {
            let mut planes = Planes::new();
            planes.load(&[value; 16])?;
            planes.substitute(inverse)?;
            let mut output = [0; 16];
            planes.store(&mut output)?;
            let table = if inverse { &inverse_table } else { &SBOX };
            assert_eq!(output, [read(table, usize::from(value))?; 16]);
            planes.substitute(!inverse)?;
            planes.store(&mut output)?;
            assert_eq!(output, [value; 16]);
        }
    }
    Ok(())
}
