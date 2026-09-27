use super::{Error, Fips202BitString, ParallelCore, Strength};
extern crate std;

// This reference groups input directly into leaf slices; it never copies
// through ParallelCore's buffering/final-tail paths under test.
fn direct_leaf_reference(
    strength: Strength,
    input: Fips202BitString<'_>,
    block: usize,
    output_bits: u128,
) -> Result<[u8; 32], Error> {
    let mut root =
        crate::core_state::Backend::outer(strength, crate::core_state::byte_string(b"")?)?;
    let mut encoding = crate::core_state::Encoded::empty();
    encoding.left(u128::try_from(block).map_err(|_| Error::InvalidBlockSize)?)?;
    root.update(encoding.bytes()?)?;
    let mut leaves = 0_u128;
    let mut position = 0_usize;
    for chunk in input.as_bytes().chunks(block) {
        position = position
            .checked_add(chunk.len())
            .ok_or(Error::MessageTooLong)?;
        let valid = if position == input.as_bytes().len() {
            input.valid_bits_in_last_byte()
        } else {
            8
        };
        let bits = Fips202BitString::new(chunk, valid).map_err(|_| Error::InvalidBitString)?;
        match strength {
            Strength::Bits128 => {
                let mut output = [0; 32];
                let secret = crate::core_state::leaf128(bits, &mut output)?;
                root.update(secret.expose())?;
            }
            Strength::Bits256 => {
                let mut output = [0; 64];
                let secret = crate::core_state::leaf256(bits, &mut output)?;
                root.update(secret.expose())?;
            }
        }
        leaves = leaves.checked_add(1).ok_or(Error::MessageTooLong)?;
    }
    encoding.right(leaves)?;
    root.update(encoding.bytes()?)?;
    encoding.right(output_bits)?;
    root.update(encoding.bytes()?)?;
    let mut output = [0; 32];
    root.finalize_in_place()?.squeeze_public(&mut output)?;
    Ok(output)
}

pub(super) fn run() -> Result<(), Error> {
    let selected = if cfg!(miri) {
        std::env::var("BRYNJA_MIRI_CASE").ok().map(|value| {
            let parsed = value.parse::<usize>();
            assert!(parsed.is_ok());
            parsed.unwrap_or(usize::MAX)
        })
    } else {
        None
    };
    assert!(selected.is_none_or(|case| case < 672));
    let mut visited = 0_usize;
    let mut executed = 0_usize;
    for strength in [Strength::Bits128, Strength::Bits256] {
        for block in [1_usize, 2, 7, 64, 136, 168, 169] {
            let before = block.checked_sub(1).ok_or(Error::StateConsumed)?;
            let after = block.checked_add(1).ok_or(Error::StateConsumed)?;
            let multiblock = block
                .checked_mul(2)
                .and_then(|n| n.checked_add(1))
                .ok_or(Error::StateConsumed)?;
            for length in [0, 1, before, block, after, multiblock] {
                for valid in 1_u8..=8 {
                    let index = visited;
                    visited = visited.checked_add(1).ok_or(Error::StateConsumed)?;
                    if selected.is_some_and(|case| case != index) {
                        continue;
                    }
                    executed = executed.checked_add(1).ok_or(Error::StateConsumed)?;
                    let mut input = [0_u8; 339];
                    for (index, byte) in input.iter_mut().enumerate() {
                        *byte = index.to_le_bytes()[0].wrapping_mul(29).wrapping_add(0xa5);
                    }
                    let input = input.get_mut(..length).ok_or(Error::StateConsumed)?;
                    if let Some(last) = input.last_mut() {
                        *last &=
                            u8::MAX >> 8_u8.checked_sub(valid).ok_or(Error::InvalidBitString)?;
                    }
                    let bits = Fips202BitString::new(input, if length == 0 { 0 } else { valid })
                        .map_err(|_| Error::InvalidBitString)?;
                    for output_bits in [0, 256] {
                        let expected = direct_leaf_reference(strength, bits, block, output_bits)?;
                        let mut storage = [0xa5; 169];
                        let storage = storage.get_mut(..block).ok_or(Error::StateConsumed)?;
                        let mut owner = ParallelCore::new(
                            storage,
                            strength,
                            crate::core_state::byte_string(b"")?,
                        )?;
                        if let Some((last, prefix)) = input.split_last() {
                            for chunk in prefix.chunks(13) {
                                owner.update(chunk)?;
                            }
                            owner.finalize_input(Some(
                                Fips202BitString::new(core::slice::from_ref(last), valid)
                                    .map_err(|_| Error::InvalidBitString)?,
                            ))?;
                        } else {
                            owner.finalize_input(Some(bits))?;
                        }
                        assert!(owner.workspace.iter().all(|byte| *byte == 0));
                        assert_eq!(owner.used()?, 0);
                        let mut output = [0xa5; 32];
                        let mut reader = owner.finish(None, output_bits)?;
                        let secret = reader.squeeze_secret(&mut output)?;
                        assert_eq!(secret.expose(), expected);
                        drop(secret);
                        assert_eq!(output, [0; 32]);
                    }
                }
            }
        }
    }
    assert_eq!(visited, 672);
    assert_eq!(executed, if selected.is_some() { 1 } else { 672 });
    #[cfg(miri)]
    if let Some(case) = selected {
        std::println!("\nMIRI_CASE_PASS: parallelhash-buffering:{case}");
    }
    Ok(())
}
