//! Source-only post-encoding injection. This checkpoint changes test codegen;
//! it is not an emitted instruction or a qualified production fault site.
extern crate std;
use super::super::capture::evidence_tests::Mutation;
use super::*;
use core::cell::Cell;

#[derive(Clone, Copy)]
enum Replica {
    Primary,
    Complemented,
}
std::thread_local! {
    static PLAN: Cell<Option<(Replica, usize, Mutation)>> = const { Cell::new(None) };
    static HITS: Cell<usize> = const { Cell::new(0) };
}
struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        PLAN.set(None);
    }
}
fn inject(replica: Replica, position: usize, mutation: Mutation) -> Reset {
    assert!(PLAN.get().is_none());
    PLAN.set(Some((replica, position, mutation)));
    HITS.set(0);
    Reset
}
pub(super) fn checkpoint(primary: &mut [u8], complemented: &mut [u8]) {
    if let Some((replica, position, mutation)) = PLAN.get() {
        let target = match replica {
            Replica::Primary => primary,
            Replica::Complemented => complemented,
        };
        if let Some(byte) = target.get_mut(position) {
            *byte = mutation.apply(*byte);
            HITS.set(HITS.get().wrapping_add(1));
        }
    }
}

#[test]
fn post_encoding_all_bytes_mutations_reject_or_preserve_correct_import() -> Result<(), Error> {
    let mut rejected = 0usize;
    let mut unchanged = 0usize;
    for width in [16usize, 24, 32] {
        for replica in [Replica::Primary, Replica::Complemented] {
            for position in 0..width {
                for mutation in super::super::capture::evidence_tests::mutations() {
                    let key = [0x42; 32];
                    let mut primary = [0x91; 34];
                    let mut secondary = [0x92; 34];
                    let end = width.wrapping_add(1);
                    let reset = inject(replica, position, mutation);
                    {
                        let result = Keys::new_profile(
                            key.get(..width).ok_or(Error::SecretMemory)?,
                            primary.get_mut(1..end).ok_or(Error::SecretMemory)?,
                            secondary.get_mut(1..end).ok_or(Error::SecretMemory)?,
                        );
                        assert_eq!(HITS.get(), 1);
                        drop(reset);
                        let original = match replica {
                            Replica::Primary => 0x42,
                            Replica::Complemented => !0x42,
                        };
                        match result {
                            Ok(keys) => {
                                assert_eq!(mutation.apply(original), original);
                                assert!(keys.primary.iter().all(|v| *v == 0x42));
                                assert!(keys.complemented.iter().all(|v| *v == !0x42));
                                drop(keys);
                                unchanged = unchanged.wrapping_add(1);
                            }
                            Err(error) => {
                                assert_ne!(mutation.apply(original), original);
                                assert_eq!(error, ProfileFailure::ImportRejected);
                                rejected = rejected.wrapping_add(1);
                            }
                        }
                    }
                    assert_eq!(key, [0x42; 32]);
                    assert!(
                        primary
                            .get(1..end)
                            .ok_or(Error::SecretMemory)?
                            .iter()
                            .all(|v| *v == 0)
                    );
                    assert!(
                        secondary
                            .get(1..end)
                            .ok_or(Error::SecretMemory)?
                            .iter()
                            .all(|v| *v == 0)
                    );
                    assert_eq!(primary.first(), Some(&0x91));
                    assert_eq!(secondary.first(), Some(&0x92));
                    assert!(
                        primary
                            .get(end..)
                            .ok_or(Error::SecretMemory)?
                            .iter()
                            .all(|v| *v == 0x91)
                    );
                    assert!(
                        secondary
                            .get(end..)
                            .ok_or(Error::SecretMemory)?
                            .iter()
                            .all(|v| *v == 0x92)
                    );
                }
            }
        }
    }
    assert_eq!((rejected, unchanged), (137_376, 9_936));
    Ok(())
}

#[test]
fn post_encoding_faults_propagate_through_both_owners_and_all_block_paths() -> Result<(), Error> {
    let plain = super::tests::answer("00112233445566778899aabbccddeeff")?;
    let mut cases = 0usize;
    for width in [16usize, 24, 32] {
        let cipher = super::tests::answer(match width {
            16 => "69c4e0d86a7b0430d8cdb78070b4c55a",
            24 => "dda97ca4864cdfe06eaf70a0ec0d7191",
            32 => "8ea2b7ca516745bfeafc49904b496089",
            _ => return Err(Error::SecretMemory),
        })?;
        for replica in [Replica::Primary, Replica::Complemented] {
            for position in 0..width {
                let position_byte = u8::try_from(position).map_err(|_| Error::SecretMemory)?;
                let original = if matches!(replica, Replica::Primary) {
                    position_byte
                } else {
                    !position_byte
                };
                for effective in [false, true] {
                    let mutation = if effective {
                        Mutation::Xor(1)
                    } else {
                        Mutation::Replace(original)
                    };
                    for local in [false, true] {
                        for path in 0..3 {
                            let mut key = [0; 32];
                            for (byte, value) in key.iter_mut().zip(0u8..32) {
                                *byte = value;
                            }
                            let mut primary = [0x91; 34];
                            let mut secondary = [0x92; 34];
                            let end = width.wrapping_add(1);
                            let mut output = [0x93; 16];
                            let input = if path == 2 { cipher } else { plain };
                            let expected = if path == 2 { plain } else { cipher };
                            let reset = inject(replica, position, mutation);
                            {
                                macro_rules! check_owner {
                                    ($constructor:expr) => {{
                                        let imported = $constructor;
                                        assert_eq!(HITS.get(), 1);
                                        drop(reset);
                                        if effective {
                                            assert!(matches!(
                                                imported,
                                                Err(ProfileFailure::ImportRejected)
                                            ));
                                            assert_eq!(output, [0x93; 16]);
                                        } else {
                                            let mut owner = imported.map_err(Error::from)?;
                                            if path == 0 {
                                                owner
                                                    .encrypt_public_profile(
                                                        &input,
                                                        &mut output,
                                                        PublicCiphertext::acknowledge(),
                                                    )
                                                    .map_err(Error::from)?;
                                                assert_eq!(output, expected);
                                            } else {
                                                let block = owner
                                                    .secret_profile(&input, &mut output, path == 2)
                                                    .map_err(Error::from)?;
                                                assert_eq!(block.expose(), &expected);
                                                drop(block);
                                                assert_eq!(output, [0; 16]);
                                            }
                                            drop(owner);
                                        }
                                    }};
                                }
                                if local {
                                    check_owner!(ephemeral::Ephemeral::new_profile(
                                        key.get(..width).ok_or(Error::SecretMemory)?,
                                        primary.get_mut(1..end).ok_or(Error::SecretMemory)?,
                                        secondary.get_mut(1..end).ok_or(Error::SecretMemory)?,
                                    ));
                                } else {
                                    check_owner!(Cached::new_profile(
                                        key.get(..width).ok_or(Error::SecretMemory)?,
                                        primary.get_mut(1..end).ok_or(Error::SecretMemory)?,
                                        secondary.get_mut(1..end).ok_or(Error::SecretMemory)?,
                                    ));
                                }
                            }
                            assert!(key.iter().zip(0u8..32).all(|(a, b)| *a == b));
                            for (storage, sentinel) in [(&primary, 0x91), (&secondary, 0x92)] {
                                assert_eq!(storage.first(), Some(&sentinel));
                                assert!(
                                    storage
                                        .get(1..end)
                                        .ok_or(Error::SecretMemory)?
                                        .iter()
                                        .all(|v| *v == 0)
                                );
                                assert!(
                                    storage
                                        .get(end..)
                                        .ok_or(Error::SecretMemory)?
                                        .iter()
                                        .all(|v| *v == sentinel)
                                );
                            }
                            cases = cases.wrapping_add(1);
                        }
                    }
                }
            }
        }
    }
    assert_eq!(cases, 1_728);
    Ok(())
}
