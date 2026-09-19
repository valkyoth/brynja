extern crate std;
use super::*;
use crate::hardened::accelerated::{Reader, Sha3PublicDeclassification};
use brynja_crypto_cpu::static_execution::{Authority, Kernel};

fn cleared(memory: &Memory) -> bool {
    [
        &memory.lanes[..],
        &memory.message_count,
        &memory.output_count,
        &memory.suffix,
    ]
    .into_iter()
    .all(|region| region.iter().all(|b| *b == 0))
}

#[test]
fn every_memory_region_is_explicitly_cleared() {
    let mut memory = Memory::new();
    memory.lanes.fill(0xa5);
    memory.message_count.fill(0xb6);
    memory.output_count.fill(0xc7);
    memory.suffix.fill(0xd8);
    memory.wipe();
    assert!(cleared(&memory));
}

fn authority() -> Result<Option<Authority>, Error> {
    let compiled = cfg!(all(target_arch = "x86_64", target_feature = "avx2"))
        || cfg!(all(target_arch = "aarch64", target_feature = "sha3"));
    let kernel = if cfg!(target_arch = "aarch64") {
        Kernel::ArmKeccak
    } else {
        Kernel::X86Keccak
    };
    if compiled {
        Authority::new(kernel).map(Some).map_err(Error::Backend)
    } else {
        Ok(None)
    }
}
fn engine(owner: &Authority) -> Result<Engine<'_>, Error> {
    Engine::new(
        KeccakSession::from_static(owner).map_err(Error::Backend)?,
        136,
    )
}

#[test]
fn borrowed_squeeze_chunks_preserve_rate_position_and_counters() -> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    for rate in [136, 168] {
        let mut expected = [0; 1024];
        if rate == 136 {
            let mut reference = crate::Shake256::new();
            reference
                .update(b"borrowed sponge")
                .map_err(|_| Error::Terminal)?;
            reference
                .finalize_xof()
                .squeeze(&mut expected)
                .map_err(|_| Error::Terminal)?;
        } else {
            let mut reference = crate::Shake128::new();
            reference
                .update(b"borrowed sponge")
                .map_err(|_| Error::Terminal)?;
            reference
                .finalize_xof()
                .squeeze(&mut expected)
                .map_err(|_| Error::Terminal)?;
        }
        let mut state = Engine::new(
            KeccakSession::from_static(&owner).map_err(Error::Backend)?,
            rate,
        )?;
        state.update(b"borrowed ")?;
        state.update(b"sponge")?;
        state.finish(crate::hardened::accelerated::empty()?, 0x1f, 5)?;
        let mut offset = 0;
        for length in [0, 1, rate - 1, 0, rate, rate + 1, 2 * rate + 7] {
            let mut storage = std::vec![0xa5; length + 2];
            let end = offset + length;
            state.read(storage.get_mut(1..length + 1).ok_or(Error::Terminal)?)?;
            assert_eq!(storage.get(1..length + 1), expected.get(offset..end));
            assert_eq!(storage.first(), Some(&0xa5));
            assert_eq!(storage.last(), Some(&0xa5));
            assert_eq!(read_count(&state.memory.output_count), end as u128);
            assert_eq!(
                state.position,
                if end == 0 { 0 } else { 1 + (end - 1) % rate }
            );
            offset = end;
        }
        state.cancel();
        assert!(cleared(&state.memory));
    }
    Ok(())
}

#[test]
fn invalid_squeeze_range_clears_owner_and_preserves_public_destination() -> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    for (rate, position) in [(136, 137), (136, usize::MAX), (0, 0)] {
        let mut state = engine(&owner)?;
        state.memory.lanes.fill(0xa5);
        state.rate = rate;
        state.position = position;
        state.squeezing = true;
        let mut output = [0x93; 4];
        let mut scratch = [0x5a; 6];
        assert_eq!(
            state.read_public(
                &mut output,
                &mut scratch,
                Sha3PublicDeclassification::acknowledge()
            ),
            Err(Error::Terminal)
        );
        assert_eq!(output, [0x93; 4]);
        assert_eq!(scratch, [0; 6]);
        assert!(cleared(&state.memory));
        assert_eq!(state.check(true), Err(Error::Terminal));
    }
    Ok(())
}

#[test]
fn borrowed_reader_and_in_place_final_masks_preserve_low_bits() -> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    for valid in 1..=8 {
        let mut expected = [0; 337];
        let mut reference = crate::Shake256::new();
        reference.update(b"abc").map_err(|_| Error::Terminal)?;
        reference
            .finalize_xof()
            .squeeze(&mut expected)
            .map_err(|_| Error::Terminal)?;
        *expected.last_mut().ok_or(Error::Terminal)? &= u8::MAX >> (8 - valid);
        for secret in [false, true] {
            let mut state = engine(&owner)?;
            state.update(b"abc")?;
            state.finish(crate::hardened::accelerated::empty()?, 0x1f, 5)?;
            let reader = Reader { engine: state };
            let mut output = [0xa5; 337];
            let mut scratch = [0x5a; 339];
            if secret {
                let result = reader.squeeze_final_bits_secret(&mut output, valid)?;
                assert_eq!(result.expose(), &expected);
                drop(result);
                assert_eq!(output, [0; 337]);
            } else {
                reader.squeeze_final_bits_public(
                    crate::Fips202Output::new(&mut output, valid)
                        .map_err(|_| Error::OutputLength)?,
                    &mut scratch,
                    Sha3PublicDeclassification::acknowledge(),
                )?;
                assert_eq!(output, expected);
                assert_eq!(scratch, [0; 339]);
            }
        }
        let mut state = crate::hardened::accelerated::Shake256::new(
            KeccakSession::from_static(&owner).map_err(Error::Backend)?,
        )?;
        state.update(b"abc")?;
        state.enter_squeezing_in_place(crate::hardened::accelerated::empty()?)?;
        let mut output = [0xa5; 337];
        let mut scratch = [0x5a; 339];
        state.squeeze_final_bits_public_in_place(
            crate::Fips202Output::new(&mut output, valid).map_err(|_| Error::OutputLength)?,
            &mut scratch,
            Sha3PublicDeclassification::acknowledge(),
        )?;
        assert_eq!(output, expected);
        assert_eq!(scratch, [0; 339]);
        assert_eq!(
            state.squeeze_public_in_place(
                &mut output,
                &mut scratch,
                Sha3PublicDeclassification::acknowledge()
            ),
            Err(Error::Terminal)
        );
        assert_eq!(output, expected);
    }
    Ok(())
}

#[test]
fn borrowed_partial_high_bits_survive_suffix_boundary() -> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    for rate in [136, 168] {
        for length in [rate - 1, rate, rate + 1] {
            for valid in 1..=7 {
                let mut message = std::vec![0x96; length + 1];
                *message.last_mut().ok_or(Error::Terminal)? = 1 << (valid - 1);
                let bits = Fips202BitString::new(&message, valid).map_err(|_| Error::Terminal)?;
                let mut expected = [0; 201];
                if rate == 136 {
                    crate::Shake256::new()
                        .finalize_bits_xof(bits)
                        .map_err(|_| Error::Terminal)?
                        .squeeze(&mut expected)
                        .map_err(|_| Error::Terminal)?;
                } else {
                    crate::Shake128::new()
                        .finalize_bits_xof(bits)
                        .map_err(|_| Error::Terminal)?
                        .squeeze(&mut expected)
                        .map_err(|_| Error::Terminal)?;
                }
                let mut state = Engine::new(
                    KeccakSession::from_static(&owner).map_err(Error::Backend)?,
                    rate,
                )?;
                state.update(message.get(..17).ok_or(Error::Terminal)?)?;
                state.finish(
                    Fips202BitString::new(message.get(17..).ok_or(Error::Terminal)?, valid)
                        .map_err(|_| Error::Terminal)?,
                    0x1f,
                    5,
                )?;
                let mut output = [0xa5; 201];
                state.read(&mut output)?;
                assert_eq!(output, expected);
                state.cancel();
                assert!(cleared(&state.memory));
            }
        }
    }
    Ok(())
}

#[test]
fn late_squeeze_errors_clear_state_and_secret_output_but_preserve_public_output()
-> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    for secret in [false, true] {
        let mut engine = engine(&owner)?;
        engine.update(b"secret")?;
        engine.finish(crate::hardened::accelerated::empty()?, 0x1f, 5)?;
        engine.remaining_permutations = Some(1);
        let mut reader = Reader { engine };
        let mut output = [0xa5; 500];
        let mut scratch = [0x5a; 501];
        if secret {
            assert!(reader.squeeze_secret(&mut output).is_err());
            assert_eq!(output, [0; 500]);
        } else {
            assert!(
                reader
                    .squeeze_public_with_scratch(
                        &mut output,
                        &mut scratch,
                        Sha3PublicDeclassification::acknowledge()
                    )
                    .is_err()
            );
            assert_eq!(output, [0xa5; 500]);
            assert_eq!(scratch, [0; 501]);
        }
        assert!(reader.engine.failed);
        assert!(cleared(&reader.engine.memory));
        assert_eq!(reader.engine.check(true), Err(Error::Terminal));
    }
    Ok(())
}

#[test]
fn overflow_and_unwind_terminate_and_clear_the_owner() -> Result<(), Error> {
    let Some(owner) = authority()? else {
        return Ok(());
    };
    let mut state = engine(&owner)?;
    state.memory.message_count.fill(0xff);
    assert_eq!(state.update(b"x"), Err(Error::LengthOverflow));
    assert!(cleared(&state.memory));
    let mut state = engine(&owner)?;
    state.update(b"secret")?;
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _operation = Operation::new(&mut state);
        std::panic::resume_unwind(std::boxed::Box::new("hardened sponge unwind"));
    }));
    assert!(result.is_err());
    assert!(state.failed);
    assert!(cleared(&state.memory));
    Ok(())
}
