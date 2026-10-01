use super::*;
fn engine() -> Engine<'static> {
    Engine {
        bytes: Vec::new(),
        lifetime: core::marker::PhantomData,
    }
}

#[test]
fn fragmented_prefix_matches_independent_bit_concatenation() {
    for rate in [136, 168] {
        for (n, s) in [(0, 0), (1, 1), (3, 9), (8, 7), (13, 16), (0, 13), (16, 0)] {
            let mut engine = engine();
            let mut prefix = Prefix::new(&mut engine, rate, n, s).unwrap();
            for (name, bits) in [(true, n), (false, s)] {
                for bit in 0..bits {
                    let byte = [u8::from(bit % 3 == 0)];
                    prefix
                        .push(&mut engine, name, Fips202BitString::new(&byte, 1).unwrap())
                        .unwrap();
                }
            }
            prefix.complete().unwrap();
            assert_eq!(prefix.pending, [0]);
            assert_eq!(prefix.used, 0);
            let mut expected = Vec::new();
            if n != 0 || s != 0 {
                let mut bits = Vec::new();
                // Values in this model fit one-byte encodings. Build each bit
                // directly, independently of the production packer/left_encode.
                for byte in [1, rate as u8, 1, n as u8] {
                    for i in 0..8 {
                        bits.push((byte >> i) & 1);
                    }
                }
                for bit in 0..n {
                    bits.push(u8::from(bit % 3 == 0));
                }
                for byte in [1, s as u8] {
                    for i in 0..8 {
                        bits.push((byte >> i) & 1);
                    }
                }
                for bit in 0..s {
                    bits.push(u8::from(bit % 3 == 0));
                }
                expected.resize(rate, 0);
                for (i, bit) in bits.into_iter().enumerate() {
                    expected[i / 8] |= bit << (i % 8);
                }
            }
            assert_eq!(engine.bytes, expected);
        }
    }
}

#[test]
fn completion_requires_every_independent_proof_field() {
    for corrupt in 0..4 {
        let mut engine = engine();
        let mut prefix = Prefix::new(&mut engine, 168, 1, 1).unwrap();
        prefix
            .push(&mut engine, true, Fips202BitString::new(&[1], 1).unwrap())
            .unwrap();
        prefix
            .push(&mut engine, false, Fips202BitString::new(&[0], 1).unwrap())
            .unwrap();
        prefix.complete().unwrap();
        match corrupt {
            0 => prefix.phase = Phase::Name,
            1 => prefix.remaining = 1,
            2 => prefix.used = 1,
            _ => prefix.emitted -= 1,
        }
        assert_eq!(prefix.complete(), Err(Error::Terminal));
    }
}

#[test]
fn prefix_rejects_overflow_wrong_phase_and_excess_before_absorption() {
    for (n, s) in [(u128::MAX, 0), (0, u128::MAX), (u128::MAX, u128::MAX)] {
        let mut engine = engine();
        assert!(Prefix::new(&mut engine, 168, n, s).is_err());
        assert!(engine.bytes.is_empty());
    }
    for name in [false, true] {
        let mut engine = engine();
        let mut prefix = Prefix::new(&mut engine, 136, 1, 1).unwrap();
        let before = engine.bytes.clone();
        assert!(
            prefix
                .push(&mut engine, name, Fips202BitString::new(&[0], 2).unwrap())
                .is_err()
        );
        assert_eq!(engine.bytes, before);
    }
}
