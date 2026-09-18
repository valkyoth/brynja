//! Independent mappings for native transfer and Miri/Kani reference paths.
use super::{Error, Workspace};

#[test]
fn byte_and_word_transfers_preserve_all_lane_identities() -> Result<(), Error> {
    let mut seed = 0x6a09_e667_f3bc_c908_u64;
    for _ in 0..32 {
        let mut words = [[0_u64; 25]; 4];
        let mut bytes = [[0; 200]; 4];
        for (state, encoded) in words.iter_mut().zip(&mut bytes) {
            for (word, encoded) in state.iter_mut().zip(encoded.as_chunks_mut::<8>().0) {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                *word = seed;
                *encoded = word.to_le_bytes();
            }
        }
        for width in [2, 4] {
            for byte_input in [false, true] {
                let mut s = Workspace::new();
                s.state.fill([0xa5; 32]);
                s.columns.fill([0xa5; 32]);
                s.deltas.fill([0xa5; 32]);
                s.staging.fill([0xa5; 32]);
                if byte_input {
                    s.pack_bytes(&bytes, width)?;
                } else {
                    s.pack(&words, width)?;
                }
                assert!(
                    s.columns
                        .iter()
                        .chain(&s.deltas)
                        .chain(&s.staging)
                        .flatten()
                        .all(|byte| *byte == 0)
                );
                for (word, row) in s.state.iter_mut().enumerate() {
                    for (lane, (actual, state)) in row
                        .as_chunks_mut::<8>()
                        .0
                        .iter_mut()
                        .zip(&words)
                        .enumerate()
                    {
                        assert_eq!(
                            u64::from_ne_bytes(*actual),
                            if lane < width {
                                *state.get(word).ok_or(Error::Invariant)?
                            } else {
                                0
                            }
                        );
                        // Distinct output detects equal/opposite packing errors.
                        *actual = state.get(24 - word).ok_or(Error::Invariant)?.to_ne_bytes();
                    }
                }
                let mut out_words = [[0xa5a5_a5a5_a5a5_a5a5; 25]; 4];
                let mut out_bytes = [[0xa5; 200]; 4];
                s.commit(&mut out_words, width);
                s.commit_bytes(&mut out_bytes, width);
                for (lane, ((actual, encoded), original)) in
                    out_words.iter().zip(&out_bytes).zip(&words).enumerate()
                {
                    for ((word, bytes), expected) in actual
                        .iter()
                        .zip(encoded.as_chunks::<8>().0)
                        .zip(original.iter().rev())
                    {
                        let expected = if lane < width {
                            *expected
                        } else {
                            0xa5a5_a5a5_a5a5_a5a5
                        };
                        assert_eq!(*word, expected);
                        assert_eq!(*bytes, expected.to_le_bytes());
                    }
                }
            }
        }
    }
    Ok(())
}
