//! Bounded, replayable operation-sequence property campaign; no fuzz dependencies.
use super::*;

struct Tape(u64);
impl Tape {
    fn byte(&mut self) -> u8 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0.to_le_bytes()[0]
    }
    fn size(&mut self, limit: usize) -> usize {
        assert_ne!(limit, 0);
        usize::from(u16::from_le_bytes([self.byte(), self.byte()]))
            .checked_rem(limit)
            .unwrap_or_default()
    }
}

fn setting(name: &str, default: u64, maximum: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Ok(value) => {
            let value = value.parse::<u64>().map_err(error)?;
            if value == 0 || value > maximum {
                return Err(format!("{name} outside 1..={maximum}"));
            }
            Ok(value)
        }
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(value) => Err(error(value)),
    }
}

#[test]
fn replayable_operation_sequences() -> Result<(), String> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    let seed = setting("BRYNJA_KECCAK_PROPERTY_SEED", 17037, u64::MAX)?;
    let cases = setting("BRYNJA_KECCAK_PROPERTY_CASES", 64, 65536)?;
    let mut generator = Tape(seed);
    for case in 0..cases {
        let mut input = vec![0; generator.size(1025)];
        for byte in &mut input {
            *byte = generator.byte();
        }
        let valid = 1 + generator.byte() % 8;
        let tail_byte = [generator.byte() & (u8::MAX >> (8 - valid))];
        let tail = Fips202BitString::new(&tail_byte, valid).map_err(error)?;
        let n_byte = [generator.byte() & 7];
        let s_byte = [generator.byte() & 31];
        let n = Fips202BitString::new(
            if case % 2 == 0 { &[] } else { &n_byte },
            if case % 2 == 0 { 0 } else { 3 },
        )
        .map_err(error)?;
        let s = Fips202BitString::new(
            if case % 2 == 0 { &[] } else { &s_byte },
            if case % 2 == 0 { 0 } else { 5 },
        )
        .map_err(error)?;
        let sequence_seed = generator.0;
        macro_rules! check {
            ($reference:expr, $state:expr) => {{
                let result = (|| -> Result<(), String> {
                    let mut tape = Tape(sequence_seed);
                    let mut reference = $reference;
                    let mut state = $state;
                    let mut remaining = input.as_slice();
                    while !remaining.is_empty() {
                        let count = if case % 4 == 0 { 1 } else { 1 + tape.size(173) };
                        let (chunk, rest) = remaining.split_at(count.min(remaining.len()));
                        state.update(&[]).map_err(error)?;
                        state.update(chunk).map_err(error)?;
                        reference.update(chunk).map_err(error)?;
                        remaining = rest;
                    }
                    if case % 8 == 0 {
                        let mut output = [0xa5; 19];
                        assert!(state.squeeze_secret_in_place(&mut output).is_err());
                        assert_eq!(output, [0; 19]);
                        assert!(state.enter_squeezing_in_place(tail).is_err());
                        return Ok(());
                    }
                    state.enter_squeezing_in_place(tail).map_err(error)?;
                    if case % 8 == 1 {
                        assert!(state.enter_squeezing_in_place(tail).is_err());
                    } else if case % 8 == 2 {
                        assert!(state.update(b"after finalize").is_err());
                    } else if case % 8 == 3 {
                        state.cancel();
                    } else {
                        let mut reference = reference.finalize_bits_xof(tail).map_err(error)?;
                        for read in 0..12 {
                            let length = if read == 0 {
                                0
                            } else if read == 1 {
                                1
                            } else {
                                tape.size(341)
                            };
                            let mut expected = vec![0; length];
                            let mut output = vec![0xa5; length];
                            reference.squeeze(&mut expected).map_err(error)?;
                            if tape.byte() % 2 == 0 {
                                let secret =
                                    state.squeeze_secret_in_place(&mut output).map_err(error)?;
                                assert_eq!(secret.expose(), expected);
                                drop(secret);
                                assert!(output.iter().all(|byte| *byte == 0));
                            } else {
                                let mut scratch = vec![0x96; length + 7];
                                state
                                    .squeeze_public_in_place(
                                        &mut output,
                                        &mut scratch,
                                        cpu::Sha3PublicDeclassification::acknowledge(),
                                    )
                                    .map_err(error)?;
                                assert_eq!(output, expected);
                                assert!(scratch.iter().all(|byte| *byte == 0));
                            }
                        }
                        let length = 1 + tape.size(337);
                        let bits = 1 + tape.byte() % 8;
                        let mut expected = vec![0; length];
                        let mut output = vec![0xa5; length];
                        reference
                            .squeeze_final_bits(
                                Fips202Output::new(&mut expected, bits).map_err(error)?,
                            )
                            .map_err(error)?;
                        let secret = state
                            .squeeze_final_bits_secret_in_place(&mut output, bits)
                            .map_err(error)?;
                        assert_eq!(secret.expose(), expected);
                        drop(secret);
                        assert!(output.iter().all(|byte| *byte == 0));
                    }
                    let mut output = [0xa5; 19];
                    assert!(state.squeeze_secret_in_place(&mut output).is_err());
                    assert_eq!(output, [0; 19]);
                    let mut scratch = [0xa5; 23];
                    output.fill(0xa5);
                    assert!(
                        state
                            .squeeze_public_in_place(
                                &mut output,
                                &mut scratch,
                                cpu::Sha3PublicDeclassification::acknowledge()
                            )
                            .is_err()
                    );
                    assert_eq!(output, [0xa5; 19]);
                    assert_eq!(scratch, [0; 23]);
                    assert!(state.update(b"terminal").is_err());
                    Ok(())
                })();
                result.map_err(|failure| format!("seed={seed} case={case}: {failure}"))?;
            }};
        }
        // Assertion failures retain the replay seed/case through the test log.
        eprintln!("Keccak property replay: seed={seed} case={case}");
        check!(
            portable::Shake128::new(),
            cpu::Shake128::new(session(&owner)?).map_err(error)?
        );
        check!(
            portable::Shake256::new(),
            cpu::Shake256::new(session(&owner)?).map_err(error)?
        );
        check!(
            portable::Cshake128::new_bits(n, s).map_err(error)?,
            cpu::Cshake128::new_bits(session(&owner)?, n, s).map_err(error)?
        );
        check!(
            portable::Cshake256::new_bits(n, s).map_err(error)?,
            cpu::Cshake256::new_bits(session(&owner)?, n, s).map_err(error)?
        );
    }
    println!(
        "Hardened Keccak operation properties: PASS; seed={seed}; cases={cases}; identities=4"
    );
    Ok(())
}
