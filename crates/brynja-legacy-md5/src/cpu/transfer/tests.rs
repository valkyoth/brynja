use super::*;

#[test]
fn transfer_mapping_and_rejected_lanes_are_atomic() -> Result<(), Md5BackendError> {
    let mut seed = 0x6a09_e667_f3bc_c908_u64;
    for _ in 0..32 {
        let mut states = [[0_u8; 16]; 8];
        let mut blocks = [[0_u8; 64]; 8];
        for byte in states
            .iter_mut()
            .flatten()
            .chain(blocks.iter_mut().flatten())
        {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            *byte = seed
                .to_le_bytes()
                .first()
                .copied()
                .ok_or(Md5BackendError::Quarantined)?;
        }
        for width in [4, 8] {
            let mut s = Scratch::new();
            for (lane, (state, block)) in states.iter().zip(&blocks).enumerate().take(width) {
                pack_state(&mut s, state, lane)?;
                pack_block(&mut s, block, lane)?;
            }
            for (row, packed) in s.initial.iter().enumerate() {
                for (lane, (slot, state)) in
                    packed.as_chunks::<4>().0.iter().zip(&states).enumerate()
                {
                    assert_eq!(
                        slot,
                        if lane < width {
                            state
                                .as_chunks::<4>()
                                .0
                                .get(row)
                                .ok_or(Md5BackendError::Quarantined)?
                        } else {
                            &[0; 4]
                        }
                    );
                }
            }
            for (row, packed) in s.words.iter().enumerate() {
                for (lane, (slot, block)) in
                    packed.as_chunks::<4>().0.iter().zip(&blocks).enumerate()
                {
                    assert_eq!(
                        slot,
                        if lane < width {
                            block
                                .as_chunks::<4>()
                                .0
                                .get(row)
                                .ok_or(Md5BackendError::Quarantined)?
                        } else {
                            &[0; 4]
                        }
                    );
                }
            }
            // Independent output prevents matching pack/unpack mistakes from
            // cancelling. Fill inactive output too: advance copies all 128 bytes.
            for (row, packed) in s.work.iter_mut().enumerate() {
                for (slot, block) in packed.as_chunks_mut::<4>().0.iter_mut().zip(&blocks) {
                    slot.copy_from_slice(
                        block
                            .as_chunks::<4>()
                            .0
                            .get(15 - row)
                            .ok_or(Md5BackendError::Quarantined)?,
                    );
                }
            }
            let before_words = s.words;
            advance(&mut s);
            assert_eq!(s.initial, s.work);
            assert_eq!(s.words, before_words);
            assert_eq!(s.temporary, [[0; 32]; 3]);
            for (lane, block) in blocks.iter().enumerate() {
                let mut actual = [0xa5; 16];
                commit_state(&s, &mut actual, lane)?;
                for (row, bytes) in actual.as_chunks::<4>().0.iter().enumerate() {
                    assert_eq!(
                        bytes,
                        block
                            .as_chunks::<4>()
                            .0
                            .get(15 - row)
                            .ok_or(Md5BackendError::Quarantined)?
                    );
                }
            }
            let before_initial = s.initial;
            for lane in [8, 9, usize::MAX] {
                assert_eq!(
                    pack_state(&mut s, &[1; 16], lane),
                    Err(Md5BackendError::Quarantined)
                );
                assert_eq!(
                    pack_block(&mut s, &[2; 64], lane),
                    Err(Md5BackendError::Quarantined)
                );
                let mut output = [0xa5; 16];
                assert_eq!(
                    commit_state(&s, &mut output, lane),
                    Err(Md5BackendError::Quarantined)
                );
                assert_eq!(output, [0xa5; 16]);
                assert_eq!(s.initial, before_initial);
                assert_eq!(s.words, before_words);
            }
        }
    }
    Ok(())
}
