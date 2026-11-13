//! Evidence-only RV64 owner alignment/canary and portable differential checks.
//! Synthetic public data, not a timing experiment or independent certification.
#![forbid(unsafe_code)]
#![cfg(all(
    brynja_cpu_evidence,
    target_arch = "riscv64",
    target_endian = "little",
    target_feature = "zkne",
    target_feature = "zknd"
))]

use brynja_crypto::aes::{self as portable, PublicCiphertext, execution};

type Check<T> = Result<T, Box<dyn std::error::Error>>;

#[repr(align(16))]
struct Guarded<const N: usize>([u8; N]);

impl<const N: usize> Guarded<N> {
    fn new() -> Self {
        Self([0xa5; N])
    }

    fn region<const K: usize>(&mut self, start: usize) -> Check<&mut [u8; K]> {
        let end = start.checked_add(K).ok_or("range overflow")?;
        Ok(self.0.get_mut(start..end).ok_or("range")?.try_into()?)
    }

    fn check(&self, start: usize, size: usize, cleared: bool) -> Check<()> {
        let end = start.checked_add(size).ok_or("range overflow")?;
        assert!(
            self.0
                .get(..start)
                .ok_or("prefix")?
                .iter()
                .all(|b| *b == 0xa5)
        );
        assert!(
            self.0
                .get(end..)
                .ok_or("suffix")?
                .iter()
                .all(|b| *b == 0xa5)
        );
        if cleared {
            assert!(
                self.0
                    .get(start..end)
                    .ok_or("region")?
                    .iter()
                    .all(|b| *b == 0)
            );
        }
        Ok(())
    }
}

fn bytes<const N: usize>(seed: u64) -> [u8; N] {
    // A fixed synthetic stream, not a key generator. Wrapping is intentional.
    let mut state = seed;
    core::array::from_fn(|_| {
        state ^= state.wrapping_shl(13);
        state ^= state.wrapping_shr(7);
        state ^= state.wrapping_shl(17);
        state.to_le_bytes()[0]
    })
}

macro_rules! width {
    ($test:ident, $key:ident, $cached:ident, $expand:ident, $encrypt:ident, $decrypt:ident,
     $k:literal, $s:literal, $bits:literal) => {
        #[test]
        fn $test() -> Check<()> {
            let authority = execution::Authority::new(execution::Kernel::RiscVScalarAes)
                .map_err(|e| format!("{e:?}"))?;
            let session = authority.session().map_err(|e| format!("{e:?}"))?;
            let mut cases = 0_u64;
            // Both axes independently cover all 16 byte residues, with a
            // nonempty canary on either side of every admitted region.
            for key_offset in 1_usize..=16 {
                for schedule_offset in 1_usize..=16 {
                    let block_offset = key_offset.wrapping_add(schedule_offset) % 16 + 1;
                    let output_offset = 17_usize.wrapping_sub(block_offset);
                    let input_key = bytes::<$k>(cases.wrapping_add(1));
                    let input = bytes::<16>(cases.wrapping_add(0x1234_5678));
                    let mut input_memory = Guarded::<64>::new();
                    input_memory.region::<16>(block_offset)?.copy_from_slice(&input);
                    let mut raw_key = Guarded::<64>::new();
                    raw_key.region::<$k>(key_offset)?.copy_from_slice(&input_key);
                    let mut owned_key = Guarded::<64>::new();
                    let mut schedule = Guarded::<272>::new();
                    let mut raw_schedule = Guarded::<272>::new();
                    let mut raw_state = Guarded::<64>::new();
                    session.$expand(raw_key.region::<$k>(key_offset)?,
                        raw_schedule.region::<$s>(schedule_offset)?)
                        .map_err(|e| format!("{e:?}"))?;
                    let saved_schedule = *raw_schedule.region::<$s>(schedule_offset)?;
                    let mut output = Guarded::<64>::new();
                    let mut software_storage = [0_u8; $k];
                    let software = portable::$key::new(&input_key, &mut software_storage)
                        .map_err(|e| format!("{e:?}"))?;
                    let key = execution::$key::new(
                        &authority, raw_key.region::<$k>(key_offset)?,
                        owned_key.region::<$k>(key_offset)?,
                    ).map_err(|e| format!("{e:?}"))?;
                    let cached = execution::$cached::new(
                        &authority, raw_key.region::<$k>(key_offset)?,
                        schedule.region::<$s>(schedule_offset)?,
                    ).map_err(|e| format!("{e:?}"))?;
                    for inverse in [false, true] {
                        let mut expected = [0_u8; 16];
                        let reference = if inverse {
                            software.decrypt_block(&input, &mut expected)
                        } else {
                            software.encrypt_block(&input, &mut expected)
                        }.map_err(|e| format!("{e:?}"))?;
                        // Owners stage state internally. Exercise raw state
                        // residues directly too, not just their caller buffers.
                        raw_state.region::<16>(block_offset)?.copy_from_slice(&input);
                        if inverse {
                            session.$decrypt(raw_state.region::<16>(block_offset)?,
                                raw_schedule.region::<$s>(schedule_offset)?)
                        } else {
                            session.$encrypt(raw_state.region::<16>(block_offset)?,
                                raw_schedule.region::<$s>(schedule_offset)?)
                        }.map_err(|e| format!("{e:?}"))?;
                        assert_eq!(raw_state.region::<16>(block_offset)?, reference.expose());
                        assert_eq!(raw_schedule.region::<$s>(schedule_offset)?, &saved_schedule);
                        raw_state.check(block_offset, 16, false)?;
                        raw_schedule.check(schedule_offset, $s, false)?;
                        for cache in [false, true] {
                            let block = input_memory.region::<16>(block_offset)?;
                            let destination = output.region::<16>(output_offset)?;
                            let result = match (cache, inverse) {
                                (false, false) => key.encrypt_block(block, destination),
                                (false, true) => key.decrypt_block(block, destination),
                                (true, false) => cached.encrypt_block(block, destination),
                                (true, true) => cached.decrypt_block(block, destination),
                            }.map_err(|e| format!("{e:?}"))?;
                            assert_eq!(result.expose(), reference.expose());
                            result.clear();
                            output.check(output_offset, 16, true)?;
                            if !inverse {
                                let destination = output.region::<16>(output_offset)?;
                                if cache {
                                    cached.encrypt_block_public(block, destination, PublicCiphertext::acknowledge())
                                } else {
                                    key.encrypt_block_public(block, destination, PublicCiphertext::acknowledge())
                                }.map_err(|e| format!("{e:?}"))?;
                                assert_eq!(destination, reference.expose());
                                output.check(output_offset, 16, false)?;
                            }
                        }
                        reference.clear();
                    }
                    // Exercise explicit clear and Drop on both owner forms.
                    if cases % 2 == 0 {
                        key.clear();
                        cached.clear();
                    } else {
                        drop(key);
                        drop(cached);
                    }
                    software.clear();
                    assert_eq!(software_storage, [0; $k]);
                    owned_key.check(key_offset, $k, true)?;
                    schedule.check(schedule_offset, $s, true)?;
                    raw_key.check(key_offset, $k, false)?;
                    input_memory.check(block_offset, 16, false)?;
                    assert_eq!(raw_key.region::<$k>(key_offset)?, &input_key);
                    assert_eq!(input_memory.region::<16>(block_offset)?, &input);
                    cases = cases.checked_add(1).ok_or("count overflow")?;
                }
            }
            assert_eq!(cases, 256);
            println!("AES_RISCV_BOUNDARIES: {} 256 alignment pairs; both owners; both directions; public output; canaries; clear/drop", $bits);
            Ok(())
        }
    };
}

width!(
    aes128_boundaries,
    Aes128Key,
    Aes128ExpandedKey,
    expand128,
    encrypt128,
    decrypt128,
    16,
    176,
    128
);
width!(
    aes192_boundaries,
    Aes192Key,
    Aes192ExpandedKey,
    expand192,
    encrypt192,
    decrypt192,
    24,
    208,
    192
);
width!(
    aes256_boundaries,
    Aes256Key,
    Aes256ExpandedKey,
    expand256,
    encrypt256,
    decrypt256,
    32,
    240,
    256
);
