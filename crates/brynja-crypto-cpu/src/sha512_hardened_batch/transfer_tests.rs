//! Same mapping oracle runs against native transfers and the Miri/Kani model.
use super::{Error, Workspace};

#[test]
fn byte_and_word_transfers_preserve_all_lane_identities() -> Result<(), Error> {
    let mut seed = 0x6a09_e667_f3bc_c908_u64;
    for _ in 0..64 {
        let mut words = [[0_u64; 8]; 4];
        let mut bytes = [[0; 64]; 4];
        let mut blocks = [[0; 128]; 4];
        for ((state, encoded), block) in words.iter_mut().zip(&mut bytes).zip(&mut blocks) {
            for (word, encoded) in state.iter_mut().zip(encoded.as_chunks_mut::<8>().0) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *word = seed;
                *encoded = word.to_be_bytes();
            }
            for (index, byte) in block.iter_mut().enumerate() {
                *byte = *seed.to_be_bytes().get(index % 8).ok_or(Error::Invariant)?
                    ^ u8::try_from(index).map_err(|_| Error::Invariant)?;
            }
        }
        for width in [2, 4] {
            for byte_input in [false, true] {
                let mut s = Workspace::new();
                if byte_input {
                    s.pack_bytes(&bytes, &blocks, width)?;
                } else {
                    s.pack(&words, &blocks, width)?;
                }
                for (word, row) in s.schedule.iter().enumerate() {
                    for (lane, (actual, block)) in
                        row.as_chunks::<8>().0.iter().zip(&blocks).enumerate()
                    {
                        let actual = u64::from_ne_bytes(*actual);
                        let expected = if word < 16 && lane < width {
                            u64::from_be_bytes(
                                *block.as_chunks::<8>().0.get(word).ok_or(Error::Invariant)?,
                            )
                        } else {
                            0
                        };
                        assert_eq!(actual, expected);
                    }
                }
                for (word, (row, output)) in s.initial.iter().zip(&mut s.work).enumerate() {
                    for (lane, ((actual, output), state)) in row
                        .as_chunks::<8>()
                        .0
                        .iter()
                        .zip(output.as_chunks_mut::<8>().0)
                        .zip(&words)
                        .enumerate()
                    {
                        let actual = u64::from_ne_bytes(*actual);
                        assert_eq!(
                            actual,
                            if lane < width {
                                *state.get(word).ok_or(Error::Invariant)?
                            } else {
                                0
                            }
                        );
                        // Distinct output avoids a round-trip concealing equal
                        // and opposite pack/commit mapping errors.
                        *output = state.get(7 - word).ok_or(Error::Invariant)?.to_ne_bytes();
                    }
                }
                let mut result_words = [[0xa5a5_a5a5_a5a5_a5a5; 8]; 4];
                let mut result_bytes = [[0xa5; 64]; 4];
                s.commit(&mut result_words, width);
                s.commit_bytes(&mut result_bytes, width);
                for (lane, ((result_words, result_bytes), state)) in result_words
                    .iter()
                    .zip(&result_bytes)
                    .zip(&words)
                    .enumerate()
                {
                    for ((word, encoded), reversed) in result_words
                        .iter()
                        .zip(result_bytes.as_chunks::<8>().0)
                        .zip(state.iter().rev())
                    {
                        let expected = if lane < width {
                            *reversed
                        } else {
                            0xa5a5_a5a5_a5a5_a5a5
                        };
                        assert_eq!(*word, expected);
                        assert_eq!(*encoded, expected.to_be_bytes());
                    }
                }
            }
        }
    }
    Ok(())
}
